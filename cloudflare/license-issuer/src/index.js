// LocalGateKeys licence issuer: payment webhooks in, signed Pro licences out.
//
//   POST /webhooks/lemonsqueezy | /webhooks/paddle   -> issue + store licence
//   GET  /license/<token>                            -> HTML page with LGK1- key and an install link
//   GET  /license/<token>/file                       -> .lgklicense download
//   GET  /recover, POST /recover                     -> find a licence by order id + email
//   POST /appstore/claim                             -> App Store transaction JWS -> {"licence": "LGK1-..."}
//   POST /webhooks/appstore                          -> App Store refunds / revocations -> revoke: records
//   POST /play/claim                                 -> Play purchase token -> {"licence": "LGK1-..."}
//   POST /webhooks/play                              -> Play refunds (Pub/Sub push) -> revoke: records
//   cron 0 4 * * *                                   -> Play voided purchases backstop
//
// Everything else is 404 and there is no CORS. Secrets and vars: see README.md.
// `handle(request, env, deps)` is the testable entry; `env` holds only bindings,
// secrets and vars.

import {
  configuredProductIds,
  fetchPaddleCustomer,
  parseLemonSqueezy,
  parseLemonSqueezyRefund,
  parsePaddle,
  parsePaddleAdjustment,
  verifyLemonSqueezy,
  verifyPaddle,
} from "./providers.js";
import {
  buildLicense,
  encodePaste,
  fallbackTokenForOrder,
  issueBundle,
  licenseIdForOrder,
  recoveryThrottleKey,
  throttleKey,
} from "./sign.js";
import { APPLE_ROOT_G3_SHA256, decodeNotification, verifyAppleJws } from "./appstore.js";
import { appStoreAlert, sendSalesAlert } from "./sales-alert.js";
import { AppStoreApiError, appStoreApiConfigured, getAppStoreTransaction } from "./appstore-api.js";
import {
  PLAY_ORDER_ID,
  PLAY_PACKAGE,
  PLAY_PRODUCT,
  PURCHASE_TOKEN,
  PlayError,
  getPlayPurchase,
  revokePlayOrder,
  syncVoided,
  verifyGoogleOidc,
} from "./play.js";
import { issueStoreLicence, revokeStoreClaim, writeRevocation } from "./store-claims.js";

export { issueStoreLicence };

const PENDING_GIVE_UP_SECONDS = 10 * 60;
// KV caches reads at the edge, "not found" included, for 60 s by default. The
// pending page polls before the webhook lands, so ask for the shortest cache
// KV allows (30 s) to show a fresh licence sooner.
const LICENSE_CACHE_TTL_SECONDS = 30;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_FORM_BYTES = 4 * 1024;
const TOKEN_PATH = /^\/license\/([A-Za-z0-9_-]{43})(\/file)?$/;
const RECOVER_PATH = "/recover";
// Opens the desktop app, which verifies the key and asks before installing it.
const INSTALL_LINK = "localgatekeys://install-licence/";
const ORDER_ID = /^[A-Za-z0-9_-]{1,64}$/;
// Per-email /recover throttle (review R-6), on top of the Cloudflare rule
// "Licence recovery limit" (3 requests / 10 s per IP) on the zone.
const RECOVER_MAX_ATTEMPTS = 5;
const RECOVER_WINDOW_SECONDS = 60 * 60;
// Store claims (/appstore/claim, /play/claim): the same KV throttle, per client
// IP. Apps claim once per purchase and retry on the next launch, so 20 an hour
// leaves room for several phones behind one carrier NAT.
const STORE_CLAIM_MAX_ATTEMPTS = 20;
const STORE_PRODUCT_ID = "pro_unlimited";
// On every response: licence pages are never framed, indexed or cached, and
// the host is HTTPS-only (no `preload` until the owner decides on it).
const PAGE_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "Cache-Control": "no-store",
};
const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

function respond(status, body, contentType = "text/plain; charset=utf-8", extra = {}) {
  return new Response(body, { status, headers: { ...PAGE_HEADERS, "Content-Type": contentType, ...extra } });
}

const plain = (status, message) => respond(status, `${message}\n`);

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

function page(title, inner, head = "", extra = {}, status = 200) {
  return respond(
    status,
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
      `<meta name="viewport" content="width=device-width,initial-scale=1">` +
      `<title>${escapeHtml(title)}</title>${head}` +
      `<style>body{font:16px system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}` +
      `textarea{width:100%;height:9rem;font:12px monospace}` +
      `a.install{display:inline-block;padding:.6rem 1.1rem;border-radius:.5rem;background:#1f5eff;color:#fff;text-decoration:none;font-weight:600}</style></head><body>${inner}</body></html>`,
    "text/html; charset=utf-8",
    extra,
  );
}

async function readBody(request, limit = MAX_BODY_BYTES) {
  const declared = Number(request.headers.get("Content-Length"));
  if (Number.isFinite(declared) && declared > limit) return null;
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length > limit) return null;
  return new TextDecoder().decode(bytes);
}

// Test seams live here, not in `env`: production env holds only bindings,
// secrets and vars. `deps.now` is epoch milliseconds, `deps.fetch` a fetch.
function nowMs(deps) {
  return deps.now !== undefined ? Number(deps.now) : Date.now();
}

// KV keys (namespace LICENSES):
//   order:<provider>:<order id>          -> the token the buyer is shown (claim or own token)
//   order-license:<provider>:<order id>  -> license_id of that order
//   claim:<token>                        -> (old deploys only) the order key a claim was bound to
//   license:<token>                      -> signed licence bundle (JSON), under the order's
//                                           own token and, if it won it, the claim
//   adjustment:<provider>:<id>           -> refund / chargeback record (JSON, also as metadata)
//   revoke:<license_id>:<adjustment id>  -> the same record, listed by the operator to revoke
//   recover-throttle:<HMAC(email)>       -> /recover attempts for that email this hour (JSON)
//
// D1 (binding CLAIMS, migrations/0001_claims.sql) decides which order owns a
// browser claim: `claim` is the primary key, so of two orders racing for one
// claim exactly one INSERT lands (audit L-2). KV has no compare-and-set, so it
// is never used to arbitrate.

const CLAIM_SELECT = "SELECT order_key FROM claims WHERE claim = ?1";
const CLAIM_INSERT =
  "INSERT INTO claims (claim, order_key, licence_id, created_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING";

async function claimOwner(env, claim) {
  const row = await env.CLAIMS.prepare(CLAIM_SELECT).bind(claim).first();
  return row === null ? null : row.order_key;
}

// Claims taken before D1 arbitrated them: a KV binding or a stored licence.
async function usedBeforeD1(env, orderKey, claim) {
  const bound = await env.LICENSES.get(`claim:${claim}`);
  if (bound !== null) return bound !== orderKey;
  return (await env.LICENSES.get(`license:${claim}`)) !== null;
}

// Returns true if this order owns the claim. Fails closed: no claim without
// D1 (missing binding, outage); the licence is still under the order's own token.
async function bindClaim(env, deps, orderKey, licenseId, claim) {
  if (!env.CLAIMS) {
    console.error(`license-issuer: D1 binding CLAIMS missing; ${orderKey} uses its own token, not its claim`);
    return false;
  }
  try {
    const owner = await claimOwner(env, claim);
    if (owner !== null) return owner === orderKey; // a duplicate delivery reads back its own row
    if (await usedBeforeD1(env, orderKey, claim)) {
      // A concurrent delivery of this order may have bound it and written the licence since.
      return (await claimOwner(env, claim)) === orderKey;
    }
    const createdAt = Math.floor(nowMs(deps) / 1000);
    await env.CLAIMS.prepare(CLAIM_INSERT).bind(claim, orderKey, licenseId, createdAt).run();
    return (await claimOwner(env, claim)) === orderKey;
  } catch (error) {
    console.error(`license-issuer: D1 claim binding failed for ${orderKey}; using its own token: ${error}`);
    return false;
  }
}

const orderLicenseKey = (orderKey) => `order-license:${orderKey.slice("order:".length)}`;

async function storeLicense(env, deps, orderKey, claim, buyer) {
  // Sign first: a bad key throws before anything is written. The licence id
  // comes from the order, so a duplicate delivery signs the same licence.
  const licenseId = await licenseIdForOrder(orderKey);
  const issuedAt = new Date(nowMs(deps)).toISOString().slice(0, 10);
  const license = buildLicense({ name: buyer.name, email: buyer.email, issuedAt, licenseId });
  const bundle = JSON.stringify(await issueBundle(license, env.LICENSE_PRIVATE_KEY));
  // Every order's licence is always stored under its own token, which only
  // this Worker can compute; recovery (POST /recover) leads there, so an order
  // that loses its claim never loses the licence. A claim this order won is an alias.
  const own = await fallbackTokenForOrder(orderKey, env.LICENSE_PRIVATE_KEY);
  await env.LICENSES.put(`license:${own}`, bundle);
  let token = own;
  if (claim !== null) {
    if (await bindClaim(env, deps, orderKey, licenseId, claim)) {
      await env.LICENSES.put(`license:${claim}`, bundle);
      token = claim;
    } else {
      // Flag it: the buyer's checkout page will not show this licence; /recover will.
      console.warn(`license-issuer: claim not bound to ${orderKey} (licence ${licenseId}); buyer needs /recover`);
    }
  }
  await env.LICENSES.put(orderLicenseKey(orderKey), licenseId);
  // Written last: its presence means "issued", so a retry after a partial write finishes the job.
  await env.LICENSES.put(orderKey, token);
}

// The licence id of an issued order: from the index, else (orders issued
// before the index existed) from the stored bundle.
async function licenseIdOf(env, orderKey) {
  const indexed = await env.LICENSES.get(orderLicenseKey(orderKey));
  if (indexed !== null) return indexed;
  const token = await env.LICENSES.get(orderKey);
  if (token === null) return null;
  const stored = await env.LICENSES.get(`license:${token}`);
  return stored === null ? null : (JSON.parse(stored)?.license?.license_id ?? null);
}

// Records a refund or chargeback so the operator can revoke the licence (see
// README.md, "Refunds and revocation"). Nothing is revoked here: revocation is
// a list signed offline with the release key.
async function recordAdjustment(provider, adjustment, env, deps) {
  const orderKey = `order:${provider}:${adjustment.orderId}`;
  const licenseId = await licenseIdOf(env, orderKey);
  if (licenseId === null) {
    // Another product, or an order this Worker never issued.
    console.warn(`license-issuer: ${provider} adjustment ${adjustment.adjustmentId} for unknown order ${adjustment.orderId}`);
    return plain(200, "Ignored");
  }
  const record = {
    provider,
    order_id: adjustment.orderId,
    adjustment_id: adjustment.adjustmentId,
    license_id: licenseId,
    action: adjustment.action,
    status: adjustment.status,
    type: adjustment.type,
    occurred_at: adjustment.occurredAt,
    revoke: adjustment.revoke,
    reinstate: adjustment.reinstate,
    recorded_at: new Date(nowMs(deps)).toISOString(),
  };
  // adjustment.updated overwrites the same keys with the newer status.
  await writeRevocation(env, provider, adjustment.adjustmentId, record);
  if (adjustment.revoke) console.warn(`license-issuer: licence ${licenseId} needs revoking (${adjustment.action})`);
  return plain(200, "Recorded");
}

async function webhook(provider, request, env, deps) {
  if (env.PROVIDER && env.PROVIDER !== provider) return plain(404, "Not found");
  const body = await readBody(request);
  if (body === null) return plain(413, "Payload too large");
  const verified =
    provider === "lemonsqueezy"
      ? await verifyLemonSqueezy(request, body, env)
      : await verifyPaddle(request, body, env, nowMs(deps));
  if (!verified) return plain(401, "Bad signature");
  // Checked only after the signature, so unauthenticated callers learn nothing
  // about the configuration. 500 makes the provider retry once PRODUCT_IDS is set.
  if (configuredProductIds(env).length === 0) {
    console.error("license-issuer misconfigured: PRODUCT_IDS is unset or empty; refusing to issue licences");
    return plain(500, "Issuer not configured");
  }
  let event;
  try {
    event = JSON.parse(body);
  } catch {
    return plain(400, "Malformed JSON");
  }
  const adjustment = provider === "lemonsqueezy" ? parseLemonSqueezyRefund(event) : parsePaddleAdjustment(event);
  if (adjustment !== null) return recordAdjustment(provider, adjustment, env, deps);
  const order = provider === "lemonsqueezy" ? parseLemonSqueezy(event, env) : parsePaddle(event, env);
  if (order === null) return plain(200, "Ignored");
  const orderKey = `order:${provider}:${order.orderId}`;
  if (await env.LICENSES.get(orderKey)) return plain(200, "OK"); // retried webhook: already issued
  const buyer = provider === "lemonsqueezy" ? order : await fetchPaddleCustomer(order.customerId, env, deps.fetch ?? fetch);
  await storeLicense(env, deps, orderKey, order.claim, buyer);
  return plain(200, "OK");
}

// The first visit has no `t`; its refresh URL carries the start time (epoch
// seconds) so later refreshes know how long the buyer has waited.
function pendingPage(token, env, deps, url) {
  const nowSec = Math.floor(nowMs(deps) / 1000);
  const raw = url.searchParams.get("t");
  let start = /^\d{1,12}$/.test(raw ?? "") ? Number(raw) : nowSec;
  if (start > nowSec + 60) start = nowSec; // a start time in the future is not trusted
  if (nowSec - start > PENDING_GIVE_UP_SECONDS) {
    const support = env.SUPPORT_EMAIL ? escapeHtml(env.SUPPORT_EMAIL) : "support";
    return page(
      "Still processing",
      "<h1>This is taking longer than expected</h1>" +
        `<p>This is taking longer than expected — contact ${support} with your order number.</p>` +
        `<p>If you have your receipt, you can also <a href="${RECOVER_PATH}">find your licence</a> ` +
        `with its order number and your email.</p>`,
    );
  }
  return page(
    "Processing your purchase",
    "<h1>Your purchase is being processed</h1><p>This page refreshes every few seconds. " +
      "Your licence appears here as soon as the payment is confirmed, usually within a minute. " +
      "You can keep this page open; nothing is lost if it takes longer.</p>",
    `<meta http-equiv="refresh" content="5;url=/license/${escapeHtml(token)}?t=${start}">`,
  );
}

async function licensePage(token, wantFile, env, deps, url) {
  const stored = await env.LICENSES.get(`license:${token}`, { cacheTtl: LICENSE_CACHE_TTL_SECONDS });
  if (stored === null) {
    if (wantFile) return plain(404, "Not found");
    return pendingPage(token, env, deps, url);
  }
  if (wantFile) {
    return respond(200, stored, "application/json", {
      "Content-Disposition": 'attachment; filename="LocalGateKeys-Pro.lgklicense"',
    });
  }
  const bundle = JSON.parse(stored);
  // Paddle's checkout asks for no name, so the name is often the email itself.
  const { name, email } = bundle.license;
  const holder = name === email ? escapeHtml(email) : `${escapeHtml(name)} (${escapeHtml(email)})`;
  const paste = encodePaste(bundle);
  return page(
    "Your LocalGateKeys Pro licence",
    `<h1>Your LocalGateKeys Pro licence</h1>` +
      `<p>Licensed to ${holder}.</p>` +
      `<p><a class="install" href="${INSTALL_LINK}${escapeHtml(paste)}">Install in LocalGateKeys</a></p>` +
      `<p>The app asks before it installs anything. If the button does nothing, paste this key into ` +
      `LocalGateKeys (Licence), or download the file and open it there.</p>` +
      `<textarea readonly>${escapeHtml(paste)}</textarea>` +
      `<p><a href="/license/${escapeHtml(token)}/file" download>Download LocalGateKeys-Pro.lgklicense</a></p>`,
  );
}

// Lost the licence page (closed the tab, claim bound to someone else's order)?
// The order id from the receipt plus the email it was bought with lead back to
// it. Every failure gives the same answer, so the form says nothing about which
// part was wrong. The form posts to itself only.
//
// A match must hand over the licence, so it cannot look like a miss: 303 to the
// licence page vs 404 stays. Guessing is held back instead (review R-6): every
// attempt counts against the email (5 per hour, keyed by an HMAC of it), the
// lookup does the same reads whether or not the order exists, and the zone's
// rate-limit rule caps each IP.
const RECOVER_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
};

function recoverForm(message = "", status = 200, extra = {}) {
  const note = message ? `<p role="alert">${escapeHtml(message)}</p>` : "";
  return page(
    "Find your LocalGateKeys Pro licence",
    `<h1>Find your licence</h1>${note}` +
      `<p>Enter the order or transaction number from your receipt (for Paddle it starts with <code>txn_</code>) ` +
      `and the email address you bought with.</p>` +
      `<form method="post" action="${RECOVER_PATH}">` +
      `<p><label>Order number<br><input name="order" required maxlength="64" autocomplete="off"></label></p>` +
      `<p><label>Email<br><input name="email" type="email" required maxlength="254" autocomplete="email"></label></p>` +
      `<p><button type="submit">Show my licence</button></p></form>`,
    "",
    { ...RECOVER_HEADERS, ...extra },
    status,
  );
}

function providersFor(env, orderId) {
  if (env.PROVIDER) return [env.PROVIDER];
  return orderId.startsWith("txn_") ? ["paddle"] : ["lemonsqueezy", "paddle"];
}

// Counts this attempt; returns the seconds to wait if the email is over its
// limit, else 0. KV increments are not atomic and reads may lag between
// locations, so a burst can slip a few extra attempts in; the per-IP rule
// bounds bursts. The record expires with its window.
function throttleRecovery(env, deps, email) {
  return throttle(env, deps, recoveryThrottleKey(email, env.LICENSE_PRIVATE_KEY), RECOVER_MAX_ATTEMPTS);
}

async function throttle(env, deps, keyPromise, maxAttempts) {
  const key = await keyPromise;
  const nowSec = Math.floor(nowMs(deps) / 1000);
  let state = null;
  try {
    state = JSON.parse((await env.LICENSES.get(key)) ?? "null");
  } catch {
    state = null;
  }
  if (!state || !Number.isFinite(state.reset) || !Number.isFinite(state.count) || state.reset <= nowSec) {
    state = { count: 0, reset: nowSec + RECOVER_WINDOW_SECONDS };
  }
  if (state.count >= maxAttempts) return state.reset - nowSec;
  state.count += 1;
  // KV needs an expiration at least 60 s ahead.
  await env.LICENSES.put(key, JSON.stringify(state), { expiration: Math.max(state.reset, nowSec + 60) });
  return 0;
}

function holderOf(stored) {
  if (stored === null) return "";
  try {
    return String(JSON.parse(stored)?.license?.email ?? "").trim().toLowerCase();
  } catch {
    return "";
  }
}

// The licence page an order id + email pair leads to, or null. Every provider
// tried costs the same whether or not the order exists (scan F8): one HMAC
// (the order's own token), three KV reads and one parse. The third read is the
// pre-own-token licence for old orders and a repeat of the own-token key
// otherwise, so an unknown order id and a known one with the wrong email do
// the same work. Only a match returns early, and a match is a 303 anyway.
async function findLicenceToken(env, orderId, email) {
  for (const provider of providersFor(env, orderId)) {
    const orderKey = `order:${provider}:${orderId}`;
    const own = await fallbackTokenForOrder(orderKey, env.LICENSE_PRIVATE_KEY);
    const [indexed, ownStored] = await Promise.all([env.LICENSES.get(orderKey), env.LICENSES.get(`license:${own}`)]);
    // The order's own token first (always its own licence); orders issued
    // before own tokens existed have only the indexed one.
    const legacy = indexed !== null && ownStored === null;
    const token = legacy ? indexed : own;
    const third = await env.LICENSES.get(`license:${token}`);
    const stored = indexed === null ? null : legacy ? third : ownStored;
    const holder = holderOf(stored ?? third);
    if (stored !== null && holder === email) return token;
  }
  return null;
}

async function recover(request, env, deps) {
  const notFound = () =>
    recoverForm("No licence matches that order number and email. Check both, or contact support.", 404);
  const body = await readBody(request, MAX_FORM_BYTES);
  if (body === null) return plain(413, "Payload too large");
  const form = new URLSearchParams(body);
  const orderId = (form.get("order") ?? "").trim();
  const email = (form.get("email") ?? "").trim().toLowerCase();
  if (!email.includes("@") || email.length > 254) return notFound();
  const wait = await throttleRecovery(env, deps, email);
  if (wait > 0) {
    return recoverForm(
      "Too many attempts for this email address. Try again in an hour, or contact support.",
      429,
      { "Retry-After": String(wait) },
    );
  }
  if (!ORDER_ID.test(orderId)) return notFound();
  const token = await findLicenceToken(env, orderId, email);
  if (token === null) return notFound();
  return respond(303, "", "text/plain; charset=utf-8", { Location: `/license/${token}` });
}

// --- Store purchases ------------------------------------------------------------
//
// The iPhone, Mac and Android apps claim a desktop licence right after a
// purchase or restore. Every refusal is a bare 400 "Invalid" (403 for a
// refunded purchase), so callers learn nothing about which check failed.

const json = (status, value) => respond(status, JSON.stringify(value), "application/json");
const invalid = () => plain(400, "Invalid");
const enabled = (value) => value === "1" || value === "true";

// Counts this claim against the client IP; null if allowed, else the 429.
async function throttleStoreClaim(request, env, deps) {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const wait = await throttle(env, deps, throttleKey("store-claim", ip, env.LICENSE_PRIVATE_KEY), STORE_CLAIM_MAX_ATTEMPTS);
  return wait > 0 ? respond(429, "Too many requests\n", undefined, { "Retry-After": String(wait) }) : null;
}

async function readJson(request) {
  const body = await readBody(request, MAX_FORM_BYTES * 8);
  if (body === null) return null;
  try {
    const value = JSON.parse(body);
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

async function storeLicenceResponse(env, deps, table, originalId, name) {
  if (!env.CLAIMS) {
    console.error("license-issuer: D1 binding CLAIMS missing; store claims are unavailable");
    return plain(503, "Unavailable");
  }
  const result = await issueStoreLicence(env, table, originalId, name, nowMs(deps));
  return result.revoked ? plain(403, "Revoked") : json(200, { licence: result.licence });
}

function appStoreEnvironmentAllowed(env, environment) {
  return environment === "Production" || (environment === "Sandbox" && enabled(env.APPSTORE_ALLOW_SANDBOX));
}

const appStoreBundles = (env) =>
  String(env.APPSTORE_BUNDLE_IDS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

// `deps.appleRootSha256` replaces the pinned Apple root in tests only.
const appleOptions = (deps) => ({ rootSha256: deps.appleRootSha256 ?? APPLE_ROOT_G3_SHA256, now: new Date(nowMs(deps)) });

// Logged once per isolate when the App Store Server API is not configured.
let appStoreApiWarned = false;

async function appStoreClaim(request, env, deps) {
  const limited = await throttleStoreClaim(request, env, deps);
  if (limited) return limited;
  const body = await readJson(request);
  if (body === null || typeof body.jws !== "string") return invalid();
  let tx;
  try {
    tx = await verifyAppleJws(body.jws, appleOptions(deps));
  } catch {
    return invalid();
  }
  if (!appStoreBundles(env).includes(tx.bundleId) || tx.productId !== STORE_PRODUCT_ID) return invalid();
  if (!appStoreEnvironmentAllowed(env, tx.environment)) return invalid();
  if (typeof tx.originalTransactionId !== "string" || !ORDER_ID.test(tx.originalTransactionId)) return invalid();
  if (tx.revocationDate !== undefined && tx.revocationDate !== null) return plain(403, "Revoked");
  if (appStoreApiConfigured(env)) {
    // The client's JWS can predate a refund we missed: ask Apple for its current view.
    let current;
    try {
      current = await getAppStoreTransaction(
        env,
        { transactionId: typeof tx.transactionId === "string" ? tx.transactionId : tx.originalTransactionId, environment: tx.environment, bundleId: tx.bundleId },
        deps.fetch ?? fetch,
        appleOptions(deps),
        nowMs(deps),
      );
    } catch (error) {
      if (error instanceof AppStoreApiError && error.code === "not-found") return invalid();
      return plain(503, "Unavailable");
    }
    if (current.originalTransactionId !== tx.originalTransactionId || current.bundleId !== tx.bundleId) return invalid();
    if (current.revocationDate !== undefined && current.revocationDate !== null) {
      if (!env.CLAIMS) return plain(503, "Unavailable");
      await revokeStoreClaim(
        env,
        "appstore_claims",
        tx.originalTransactionId,
        {
          adjustmentId: `refund-${tx.originalTransactionId}`,
          action: "refund",
          occurredAt: new Date(Number.isFinite(current.revocationDate) ? current.revocationDate : nowMs(deps)).toISOString(),
        },
        nowMs(deps),
      );
      return plain(403, "Revoked");
    }
  } else if (!appStoreApiWarned) {
    appStoreApiWarned = true;
    console.warn("license-issuer: App Store Server API credentials not set; claims trust the client's transaction JWS");
  }
  return storeLicenceResponse(env, deps, "appstore_claims", tx.originalTransactionId, "App Store purchase");
}

// Google Play: the token is looked up with the Play Developer API. Only a
// purchased (0), unconsumed (0) pro_unlimited counts; test purchases
// (purchaseType 0) only with PLAY_ALLOW_TEST. Google failures are 503 so the
// app retries on its next launch.
async function playClaim(request, env, deps) {
  const limited = await throttleStoreClaim(request, env, deps);
  if (limited) return limited;
  const body = await readJson(request);
  if (body === null || body.productId !== PLAY_PRODUCT || typeof body.purchaseToken !== "string") return invalid();
  if (!PURCHASE_TOKEN.test(body.purchaseToken)) return invalid();
  let purchase;
  try {
    purchase = await getPlayPurchase(env, body.purchaseToken, deps.fetch ?? fetch, nowMs(deps));
  } catch (error) {
    if (error instanceof PlayError && error.code === "invalid") return invalid();
    return plain(503, "Unavailable");
  }
  if (purchase.purchaseState === 1) return plain(403, "Revoked"); // canceled / refunded
  if (purchase.purchaseState !== 0 || purchase.consumptionState !== 0) return invalid();
  if (purchase.purchaseType === 0 && !enabled(env.PLAY_ALLOW_TEST)) return invalid();
  if (typeof purchase.orderId !== "string" || !PLAY_ORDER_ID.test(purchase.orderId)) return invalid();
  return storeLicenceResponse(env, deps, "play_claims", purchase.orderId, "Google Play purchase");
}

// Real-time Developer Notifications through a Pub/Sub push subscription. The
// push carries a Google-signed OIDC token for PLAY_PUSH_AUDIENCE minted for
// the subscription's service account PLAY_PUSH_SERVICE_ACCOUNT (401 otherwise,
// and always 401 while that var is empty). The body is never trusted on its
// own: a canceled one-time purchase (type 2) or a voided-purchase notification
// is looked up by its purchase token, and the order is revoked only if Google
// reports that purchase canceled (purchaseState 1) under the same order id.
// Anything unconfirmed is acknowledged and left to the daily Voided Purchases
// cron; anything else is acknowledged (200) so Pub/Sub does not redeliver it;
// a Google failure is 503 so it does.
async function playWebhook(request, env, deps) {
  const fetchImpl = deps.fetch ?? fetch;
  try {
    await verifyGoogleOidc(
      request.headers.get("Authorization"),
      env.PLAY_PUSH_AUDIENCE,
      env.PLAY_PUSH_SERVICE_ACCOUNT,
      fetchImpl,
      nowMs(deps),
    );
  } catch {
    return plain(401, "Unauthorized");
  }
  const body = await readJson(request);
  let note;
  try {
    note = JSON.parse(atob(body?.message?.data ?? ""));
  } catch {
    return plain(200, "Ignored");
  }
  if (note?.packageName !== PLAY_PACKAGE) return plain(200, "Ignored");
  const occurredAt = new Date(Number(note.eventTimeMillis) || nowMs(deps)).toISOString();
  const voided = note.voidedPurchaseNotification;
  const oneTime = note.oneTimeProductNotification;
  let purchaseToken;
  let notedOrderId = null;
  if (voided !== undefined && voided !== null) {
    if (typeof voided.purchaseToken !== "string") return plain(200, "Ignored");
    await sendSalesAlert(env, { title: "LocalGateKeys Pro refunded", message: "Google Play: purchase voided", tags: "warning" }, fetchImpl);
    purchaseToken = voided.purchaseToken;
    notedOrderId = typeof voided.orderId === "string" ? voided.orderId : null;
  } else if (oneTime?.notificationType === 1 && oneTime.sku === PLAY_PRODUCT) {
    // ONE_TIME_PRODUCT_PURCHASED: only the sales alert; claims issue the licence.
    await sendSalesAlert(env, { title: "LocalGateKeys Pro sold", message: "Google Play: new purchase", tags: "moneybag" }, fetchImpl);
    return plain(200, "Ignored");
  } else if (oneTime?.notificationType === 2 && oneTime.sku === PLAY_PRODUCT && typeof oneTime.purchaseToken === "string") {
    purchaseToken = oneTime.purchaseToken;
  } else {
    return plain(200, "Ignored");
  }
  if (!env.CLAIMS) return plain(503, "Unavailable");
  let purchase;
  try {
    purchase = await getPlayPurchase(env, purchaseToken, fetchImpl, nowMs(deps));
  } catch (error) {
    if (error instanceof PlayError && error.code === "invalid") return plain(200, "Ignored");
    return plain(503, "Unavailable");
  }
  if (typeof purchase.orderId !== "string" || !PLAY_ORDER_ID.test(purchase.orderId)) return plain(200, "Ignored");
  if (notedOrderId !== null && notedOrderId !== purchase.orderId) return plain(200, "Ignored");
  // purchaseState: 0 purchased, 1 canceled, 2 pending. Not canceled (yet): the cron decides.
  if (purchase.purchaseState !== 1) return plain(200, "Unconfirmed");
  await revokePlayOrder(env, purchase.orderId, occurredAt, nowMs(deps));
  return plain(200, "Recorded");
}

const APPSTORE_REVOKING = new Set(["REFUND", "REVOKE"]);

// App Store Server Notifications V2. REFUND and REVOKE mark the purchase
// revoked and write its `revoke:` record; everything else is acknowledged and
// ignored. A bad signature is 400 (Apple retries, then gives up).
async function appStoreWebhook(request, env, deps) {
  const body = await readJson(request);
  if (body === null || typeof body.signedPayload !== "string") return invalid();
  let note;
  try {
    note = await decodeNotification(body.signedPayload, appleOptions(deps));
  } catch {
    return invalid();
  }
  const tx = note.transaction;
  if (tx === null || !appStoreBundles(env).includes(tx.bundleId) || tx.productId !== STORE_PRODUCT_ID) {
    return plain(200, "Ignored");
  }
  await sendSalesAlert(env, appStoreAlert(note, tx), deps.fetch ?? fetch);
  if (!APPSTORE_REVOKING.has(note.notificationType)) return plain(200, "Ignored");
  if (!appStoreEnvironmentAllowed(env, tx.environment)) return plain(200, "Ignored");
  if (typeof tx.originalTransactionId !== "string" || !ORDER_ID.test(tx.originalTransactionId)) return invalid();
  if (!env.CLAIMS) return plain(503, "Unavailable");
  const uuid = typeof note.notificationUUID === "string" && ORDER_ID.test(note.notificationUUID) ? note.notificationUUID : null;
  await revokeStoreClaim(
    env,
    "appstore_claims",
    tx.originalTransactionId,
    {
      adjustmentId: uuid ?? `${note.notificationType.toLowerCase()}-${tx.originalTransactionId}`,
      action: note.notificationType.toLowerCase(),
      occurredAt: new Date(Number.isFinite(tx.revocationDate) ? tx.revocationDate : nowMs(deps)).toISOString(),
    },
    nowMs(deps),
  );
  return plain(200, "Recorded");
}

export async function handle(request, env, deps = {}) {
  const url = new URL(request.url);
  const { pathname } = url;
  if (request.method === "POST" && pathname === "/appstore/claim") return appStoreClaim(request, env, deps);
  if (request.method === "POST" && pathname === "/webhooks/appstore") return appStoreWebhook(request, env, deps);
  if (request.method === "POST" && pathname === "/play/claim") return playClaim(request, env, deps);
  if (request.method === "POST" && pathname === "/webhooks/play") return playWebhook(request, env, deps);
  if (request.method === "POST" && (pathname === "/webhooks/lemonsqueezy" || pathname === "/webhooks/paddle")) {
    return webhook(pathname.slice("/webhooks/".length), request, env, deps);
  }
  if (pathname === RECOVER_PATH) {
    if (request.method === "POST") return recover(request, env, deps);
    if (request.method === "GET" || request.method === "HEAD") return recoverForm();
  }
  const match = TOKEN_PATH.exec(pathname);
  if (match && (request.method === "GET" || request.method === "HEAD")) {
    return licensePage(match[1], match[2] !== undefined, env, deps, url);
  }
  return plain(404, "Not found");
}

export default {
  fetch(request, env) {
    return handle(request, env);
  },
  // Cron trigger (wrangler.jsonc): the Play voided-purchases backstop.
  scheduled(controller, env, ctx) {
    ctx.waitUntil(
      syncVoided(env, fetch).catch((error) => console.error(`license-issuer: Play voided-purchases sync failed: ${error.message}`)),
    );
  },
};
