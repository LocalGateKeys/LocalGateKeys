# LocalGateKeys licence issuer

A Cloudflare Worker that turns payment-provider webhooks into signed
LocalGateKeys Pro licences and lets the buyer retrieve them.

| Route | Purpose |
| --- | --- |
| `POST /webhooks/lemonsqueezy` | `order_created`, status `paid`; `X-Signature` HMAC-SHA256 of the body |
| `POST /webhooks/paddle` | `transaction.completed`, `adjustment.created`, `adjustment.updated`; `Paddle-Signature: ts=...;h1=...`, ts within 5 minutes |
| `GET /license/<token>` | Page with the `LGK1-` key, an "Install in LocalGateKeys" button (`localgatekeys://install-licence/<key>`) and a download link (refreshes until the webhook has arrived) |
| `GET /license/<token>/file` | `LocalGateKeys-Pro.lgklicense` download |
| `GET /recover`, `POST /recover` | Form: order / transaction id + purchase email -> 303 to that order's licence page (404 no match, 429 throttled) |
| `POST /appstore/claim` | App Store transaction JWS -> `{"licence": "LGK1-..."}` (see "Store purchases") |
| `POST /webhooks/appstore` | App Store Server Notifications V2: refunds and revocations |
| `POST /play/claim` | Google Play purchase token -> `{"licence": "LGK1-..."}` |
| `POST /webhooks/play` | Play Real-time Developer Notifications (Pub/Sub push, OIDC) |
| cron `0 4 * * *` | Play voided-purchases backstop |

Licences are lifetime: every one is issued with `updates_until` 9999-12-31, so
every build is covered and Pro removes the free 4-item limit for good.

## Retrieval token

The checkout page generates 32 random bytes (base64url, 43 characters) in the
buyer's browser, passes it as checkout custom data `lgk_claim`, and sends the
buyer to `/license/<token>` after payment.

- **Own token.** Every order's licence is stored under a token derived from
  the order key with an HMAC keyed by (a hash of) `LICENSE_PRIVATE_KEY`, so only
  the Worker can compute it and duplicate deliveries agree on it.
- **Claim.** The browser claim is bound to the first order that uses it, and
  the licence is also stored under the claim. A later order with the same
  claim keeps only its own token (logged as "claim not bound"), so the first
  buyer's page keeps showing their licence (audit L-1). The binding lives in
  D1, not KV (see "Claim binding (D1)").
- **Paddle origin.** A Paddle claim counts only on transactions with
  `origin: "web"` (opened by Paddle.js on /buy). Transactions created through
  the API or dashboard, or renewals, use the own token (audit M-2).
- **Idempotent.** `license_id` is derived from the order key, so a duplicate
  or concurrent delivery signs the same licence (audit L-2). `order:<provider>:<id>`
  (the token shown to the buyer) is written last; once present, retries are no-ops.
- **Recovery.** `/recover` takes the order or transaction id from the receipt
  and the purchase email (case-insensitive) and redirects to the order's own
  token. Every failure gives the same answer. A match has to hand over the
  licence, so a hit (303) and a miss (404) cannot look alike; guessing is held
  back instead (review R-6):
  - **Per email:** 5 attempts per hour, counted in KV under
    `recover-throttle:<HMAC(email)>` (keyed from `LICENSE_PRIVATE_KEY`, so no
    address is stored). The 6th gets 429 with `Retry-After`, right pair or
    not. KV counters are not atomic, so a burst across locations can slip a
    few extra attempts through.
  - **Per IP:** the zone's rate-limiting rule "Licence recovery limit"
    (3 requests / 10 s per IP on `/recover`, then a 10 s block). Keep it.
  - Every order tried costs one HMAC and three KV reads whether it exists, is a pre-own-token
    order, or has another email, so timing says little beyond the status (scan F8).

## Claim binding (D1)

KV has no compare-and-set, so the D1 database `lgk-licence-claims` (binding
`CLAIMS`, schema in `migrations/0001_claims.sql`) decides which order owns a
claim (audit L-2). `claim` is the primary key: the Worker runs
`INSERT ... ON CONFLICT DO NOTHING` and reads the row back, so of two orders
racing for one claim exactly one wins, and a duplicate delivery of the same
order reads back its own row and shows the same page. `order_key` is unique,
so an order binds at most one claim. The licences stay in KV.

Fails closed: if the `CLAIMS` binding is missing or D1 errors, no claim is
bound (logged); the licence is still stored under the order's own token and
`/recover` finds it. Claims bound in KV by earlier deploys (`claim:<token>`),
or with a licence stored under them, count as used.

KV keys in `LICENSES`:

| Key | Value |
| --- | --- |
| `order:<provider>:<order id>` | token shown to the buyer (claim or own token) |
| `order-license:<provider>:<order id>` | the order's `license_id` |
| `claim:<token>` | old deploys only: order key the claim was bound to (now in D1) |
| `license:<token>` | signed licence bundle (JSON) |
| `adjustment:<provider>:<adjustment id>` | refund / chargeback record (JSON, and as key metadata) |
| `revoke:<license_id>:<adjustment id>` | same record, listed to build the revocation list |
| `recover-throttle:<HMAC(email)>` | `/recover` attempts this hour (`{count, reset}`, expires with the window) |

## Setup

`workers_dev` and `preview_urls` are off; the Worker is reachable only on its
custom domain `licenses.localgatekeys.app` (the `routes` entry in `wrangler.jsonc`).
The KV namespace and D1 database below already exist and their ids are in
`wrangler.jsonc`; the commands are for a fresh setup.

```
npx wrangler kv namespace create LICENSES   # put the id into wrangler.jsonc
npx wrangler d1 create lgk-licence-claims   # put the database_id into wrangler.jsonc
npx wrangler d1 migrations apply lgk-licence-claims --remote   # 0001 claims, 0002 store claims
npx wrangler secret put LICENSE_PRIVATE_KEY # PKCS8 DER of the licence key, base64
npx wrangler secret put WEBHOOK_SECRET      # signing secret from the payment provider
npx wrangler secret put PADDLE_API_KEY      # Paddle only: reads customers
npx wrangler deploy
```

Set the non-secret settings as plain `vars` in `wrangler.jsonc`, not with
`secret put` (they are not sensitive and you want to see them in the dashboard):

```jsonc
"vars": {
  "PRODUCT_IDS": "777,pro_1",   // REQUIRED: comma-separated product ids that sell Pro
  "PROVIDER": "lemonsqueezy",    // optional: lemonsqueezy | paddle (other webhook 404s); live: paddle
  "ALLOW_TEST_MODE": "",         // "1" only while testing Lemon Squeezy test orders
  "SUPPORT_EMAIL": "support@example.com",  // shown on the pending page after 10 minutes
  "APPSTORE_BUNDLE_IDS": "app.localgatekeys.app",  // comma list: iPhone and Mac bundle ids
  "APPSTORE_ALLOW_SANDBOX": ""   // "1" only on test deployments: accept Sandbox transactions
}
```

## Store purchases (App Store, Google Play)

**Sales alerts on your phone (optional).** Install the ntfy app, subscribe to a long random topic name
(e.g. `lgk-sales-` plus 20 random characters; anyone who knows it can read the alerts), then
`npx wrangler secret put SALES_NTFY_TOPIC` with that name. Every App Store `ONE_TIME_CHARGE`, `REFUND` and
`REVOKE` notification and every Play purchase or voided purchase then sends a push (price and storefront for
Apple; sandbox ones are marked). A failed push never fails the webhook.

`POST /appstore/claim` with `{"jws": "<signedTransactionInfo>"}` (StoreKit 2
`jwsRepresentation`) answers `200 {"licence": "LGK1-..."}`, `400 Invalid`
(any check failed, no detail), `403 Revoked` or `429` (20 claims an hour per
client IP, the `/recover` throttle keyed by an HMAC of the IP). The JWS is
verified offline: ES256 with the leaf key of `x5c`, the chain up to Apple Root
CA G3 (pinned by SHA-256 in `src/appstore.js`), Apple's marker OIDs, and the
certificate dates at `signedDate`. The transaction must be `pro_unlimited`
for a bundle in `APPSTORE_BUNDLE_IDS`, not revoked, and `Production` (Sandbox
only with `APPSTORE_ALLOW_SANDBOX`).

A client JWS stays valid after a refund, so an old one would still claim if
the REFUND notification was missed. With the App Store Server API key set, the
Worker also asks Apple: Get Transaction Info
(`GET https://api.storekit.itunes.apple.com/inApps/v1/transactions/{transactionId}`,
`api.storekit-sandbox.itunes.apple.com` for Sandbox) with an ES256 JWT (`iss`,
`iat`, `exp` 20 minutes, `aud` `appstoreconnect-v1`, `bid`), verifies Apple's
`signedTransactionInfo` with the same chain check, and answers `403 Revoked`
(and writes a revoked row) if it has a `revocationDate`. An Apple error,
timeout or unverifiable answer is `503` (the app retries); a transaction Apple
does not know is `400`. Secrets (once, by the owner): App Store Connect >
Users and Access > Integrations > In-App Purchase, generate a key, then

```
npx wrangler secret put APPSTORE_API_ISSUER_ID     # the Issuer ID on that page
npx wrangler secret put APPSTORE_API_KEY_ID        # the key's Key ID
npx wrangler secret put APPSTORE_API_PRIVATE_KEY   # the whole .p8 PEM
```

Without all three the claim trusts the client's JWS as before and logs one
warning per isolate. There is no daily App Store re-check of old claims: it
would cost one Apple call per claimed purchase per day, against the Worker's
subrequest limit; App Store refunds rely on the notifications below.

One licence per original purchase: the D1 tables `appstore_claims` and
`play_claims` (migration `0002_store_claims.sql`) key on the original
transaction id / Play order id, so Restore, reinstalls and a second device get
the same key. Licences are signed with the licence key like web orders, named
"App Store purchase" or "Google Play purchase", lifetime, with no email or
other personal data (the required `email` field repeats the name).

## App Store Server Notifications

In App Store Connect > the app > App Information > App Store Server
Notifications, choose Version 2 and set **both** the Production and the
Sandbox Server URL to:

```
https://licenses.localgatekeys.app/webhooks/appstore
```

The Worker verifies `signedPayload` and the `signedTransactionInfo` inside it
with the same chain check as claims. `REFUND` and `REVOKE` for `pro_unlimited`
mark the purchase revoked in `appstore_claims` and write
`adjustment:appstore:<notificationUUID>` and `revoke:<license_id>:<notificationUUID>`
(the Paddle refund format), so the weekly revocation list picks them up. A
refund for a purchase never claimed leaves a revoked row with no licence, and
a later claim answers 403. Other notification types answer 200 and are
ignored; Sandbox notifications are ignored unless `APPSTORE_ALLOW_SANDBOX` is set;
a bad signature is 400.

## Google Play claims

`POST /play/claim` with `{"purchaseToken": "...", "productId": "pro_unlimited"}`
asks the Play Developer API (`purchases.products.get` for
`app.localgatekeys.android`) about the token. It issues only for
`purchaseState` 0 (purchased) and `consumptionState` 0; a canceled purchase is
`403`, test purchases (`purchaseType` 0) are `400` unless the var
`PLAY_ALLOW_TEST` is `1`, and a Google or configuration failure is `503` (the
app retries on its next launch). One licence per Play `orderId`; same throttle
and answers as `/appstore/claim`.

Service account (once, by the owner):

1. Google Cloud console, the project linked to Play: create a service account
   and a JSON key for it.
2. Play Console > Users and permissions: invite the service account's email,
   app access to LocalGateKeys, permission **View financial data, orders, and
   cancellation survey responses** (needed for purchase and voided-purchase
   lookups).
3. `npx wrangler secret put PLAY_SERVICE_ACCOUNT_JSON` and paste the whole JSON
   key. The Worker signs its own OAuth JWT (RS256, scope `androidpublisher`) and
   never logs access or purchase tokens.

## Google Play refunds

Real-time Developer Notifications reach `POST /webhooks/play` through Pub/Sub
(once, by the owner):

1. Google Cloud console: create a Pub/Sub topic, e.g. `play-rtdn`, and grant
   `google-play-developer-notifications@system.gserviceaccount.com` the
   **Pub/Sub Publisher** role on it.
2. Create a **push** subscription on the topic with endpoint
   `https://licenses.localgatekeys.app/webhooks/play`, **Enable authentication**
   on, a service account of your choice, and audience equal to the var
   `PLAY_PUSH_AUDIENCE` (`https://licenses.localgatekeys.app/webhooks/play`).
   Put that service account's email in the var `PLAY_PUSH_SERVICE_ACCOUNT`
   (wrangler.jsonc). Use a dedicated account for this subscription only.
3. Play Console > Monetize > Monetization setup: set the topic
   (`projects/<project>/topics/play-rtdn`) and send a test notification
   (answered 200 and ignored).

The Worker checks the push's Google-signed OIDC token (Google JWKS, issuer
accounts.google.com, audience `PLAY_PUSH_AUDIENCE`, `email` equal to
`PLAY_PUSH_SERVICE_ACCOUNT` with `email_verified` true; 401 otherwise, and
every push is 401 while that var is empty). The audience alone proves nothing:
anyone can mint a Google ID token for any audience.

The notification body is not trusted either. A `oneTimeProductNotification`
of type 2 (canceled) and a `voidedPurchaseNotification` are both looked up by
their purchase token with `purchases.products.get`; the order is revoked only
if Google reports `purchaseState` 1 (canceled) and, for a voided notification,
the same `orderId`. Otherwise the push is acknowledged (200) and the daily cron
decides. A confirmed one marks the order revoked in `play_claims` and, if it
was claimed, writes `adjustment:play:void-<orderId>` and
`revoke:<license_id>:void-<orderId>`.

A daily cron (`0 4 * * *`) reads the Voided Purchases API since the KV cursor
`play:voided:cursor` (at most 30 days back) as a backstop for missed pushes,
revoking the same way, claimed or not.

The `key_id` is derived from `LICENSE_PRIVATE_KEY` at issue time and every new
licence is verified against the derived public key before it is stored; a bad
key makes the webhook fail with 500 (the provider retries) instead of selling a
licence the app would reject. The matching public key must be in
`localvault.licensing.LICENSE_KEYS`.

`LICENSE_PRIVATE_KEY` is the licence signing key, never the release key. To
export it from the PEM made by `issue_license.py keygen`:

```
openssl pkey -in key.pem -outform DER | base64 -w0
```

Paddle does not include the buyer's email in the event, so the Worker fetches
`GET https://api.paddle.com/customers/{customer_id}`. If that call fails the
webhook returns 500 and Paddle retries.

## Paddle webhook events

In Paddle > Developer tools > Notifications, the destination for
`https://licenses.localgatekeys.app/webhooks/paddle` must subscribe to:

- `transaction.completed` (issues licences)
- `adjustment.created` and `adjustment.updated` (refunds and chargebacks)

## Refunds and revocation

The Worker never revokes anything itself. For every refund or chargeback
adjustment on an order it issued, it stores a record under
`adjustment:<provider>:<id>` and `revoke:<license_id>:<id>`; the record is
also the key's metadata, so listing the keys shows everything. Lemon Squeezy
`order_refunded` is recorded the same way. Adjustments for orders the Worker
never issued are ignored (200, logged).

A record has `revoke: true` for an approved full refund or a chargeback,
`reinstate: true` for a reversed chargeback or a rejected / reversed refund, and
neither for pending or partial refunds and chargeback warnings (review those by
hand). `adjustment.updated` overwrites the record with the new status.

To publish the revocation list (refunds.html promises revocation within 7
days; do this at least weekly while there are new records):

```powershell
# 1. What the Worker recorded
npx wrangler kv key list --binding LICENSES --prefix revoke: --remote > revoke-keys.json
# 2. Ids to revoke, keeping every id already revoked (the list replaces the old one)
node cloudflare/license-issuer/scripts/revocation-list.mjs revoke-keys.json --existing revoked.txt > revoked-new.txt
# 3. Check stderr for "review:" lines, then sign with the RELEASE key and upload
.\scripts\publish_revocations.ps1 -IdsFile .\revoked-new.txt -Key .\release-signing-key.pem
```

Keep `revoked-new.txt` as the next `revoked.txt`. `publish_revocations.ps1`
signs with `sign_release_manifest.py revocations` and uploads to the R2 bucket
`localgatekeys-releases` (use `-WhatIf` for a dry run). With no `-IdsFile` it
signs an **empty** list; publish one first so `/revocations.json` does not
404 (this has been done for the live site). Signing needs the release key, which only the owner holds.

## Test orders and products

- Lemon Squeezy orders with `meta.test_mode: true` are ignored (200) unless the
  vars entry `ALLOW_TEST_MODE` is `1`.
- Paddle has no test flag in the payload. Its sandbox uses a different API host
  (`sandbox-api.paddle.com`) and webhook secret, so the sandbox cannot mint
  licences unless you configure this Worker with sandbox credentials.
- `PRODUCT_IDS` is required. A Lemon Squeezy `first_order_item.product_id` or a
  Paddle `items[].price.product_id` must be in the list; other products are
  ignored (200). If `PRODUCT_IDS` is unset or empty the Worker fails closed:
  every correctly signed webhook returns 500 and logs a configuration error, so
  the provider retries and no order is lost once the variable is set.
- A paid Lemon Squeezy order without a usable email fails with 500 so the
  provider retries and the logs show it.

## Tests

`npm test` from the repository root runs `tests/license-issuer.test.cjs`, which
also regenerates the cross-language vectors in `tests/vectors/license/`.
`npm test` in this directory runs `test/*.test.mjs` (claims and the D1
race, recovery and its throttle, idempotency, refunds and the revocation-list
script), and the store routes: App Store JWS with a generated test CA
(`test/apple-test-ca.mjs`), claims, App Store and Play refunds with fake Google
endpoints (`test/fake-google.mjs`). `test/fake-d1.mjs` is an in-memory D1.
