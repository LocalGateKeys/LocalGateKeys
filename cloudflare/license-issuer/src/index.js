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
import { appStoreAlert, paddleRefundAlert, paddleSaleAlert, sendSalesAlert, sendSalesEmail } from "./sales-alert.js";
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
import { issueStoreLicence, reinstateStoreClaim, revokeStoreClaim, writeRevocation } from "./store-claims.js";

export { issueStoreLicence };

const PENDING_GIVE_UP_SECONDS = 10 * 60;
// KV caches reads at the edge, "not found" included, for 60 s by default. The
// pending page polls before the webhook lands, so ask for the shortest cache
// KV allows (30 s) to show a fresh licence sooner.
const LICENSE_CACHE_TTL_SECONDS = 30;
const MAX_BODY_BYTES = 64 * 1024;
// Paddle and Lemon Squeezy webhooks (scan F6): a transaction event carries every
// line item, address and payment attempt, so it gets four times the general cap.
// Still bounded: readBody stops reading past it. An over-size body is refused
// (413) on every retry, which would lose that sale, so it is logged and alerted.
const MAX_WEBHOOK_BYTES = 256 * 1024;
const MAX_FORM_BYTES = 4 * 1024;
const SITE_URL = "https://localgatekeys.app";
const TOKEN_PATH = /^\/license\/([A-Za-z0-9_-]{43})(\/file)?$/;
const RECOVER_PATH = "/recover";
// Opens the desktop app, which verifies the key and asks before installing it.
const INSTALL_LINK = "localgatekeys://install-licence/";
const ORDER_ID = /^[A-Za-z0-9_-]{1,64}$/;
// Per-email /recover throttle (review R-6), on top of the Cloudflare rule
// "Licence recovery limit" (3 requests / 10 s per IP) on the zone.
const RECOVER_MAX_ATTEMPTS = 5; // per email + order id pair
// Looser caps so a known email cannot be tried against many guessed order ids
// (Lemon Squeezy ids are enumerable), nor one order id against many emails. A
// buyer mistyping a few times stays far below them.
const RECOVER_MAX_PER_EMAIL = 15;
const RECOVER_MAX_PER_ORDER = 15;
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
  if (request.body === null) return "";
  // Count while reading: without Content-Length the body is never buffered past the cap.
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
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

// Returns "new"/"own" (truthy) if this order owns the claim, false otherwise. Fails closed: no claim without
// D1 (missing binding, outage); the licence is still under the order's own token.
async function bindClaim(env, deps, orderKey, licenseId, claim) {
  if (!env.CLAIMS) {
    console.error(`license-issuer: D1 binding CLAIMS missing; ${orderKey} uses its own token, not its claim`);
    return false;
  }
  try {
    const owner = await claimOwner(env, claim);
    if (owner !== null) return owner === orderKey ? "own" : false; // a duplicate delivery reads back its own row
    if (await usedBeforeD1(env, orderKey, claim)) {
      // A concurrent delivery of this order may have bound it and written the licence since.
      return (await claimOwner(env, claim)) === orderKey ? "own" : false;
    }
    const createdAt = Math.floor(nowMs(deps) / 1000);
    const inserted = await env.CLAIMS.prepare(CLAIM_INSERT).bind(claim, orderKey, licenseId, createdAt).run();
    if ((await claimOwner(env, claim)) !== orderKey) return false;
    // "new": this delivery bound it; "own": a concurrent delivery of the same order did.
    return inserted?.meta?.changes === 0 ? "own" : "new";
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
  const bundle = JSON.stringify(await issueBundle(license, env.LICENSE_PRIVATE_KEY, env));
  // Every order's licence is always stored under its own token, which only
  // this Worker can compute; recovery (POST /recover) leads there, so an order
  // that loses its claim never loses the licence. A claim this order won is an alias.
  const own = await fallbackTokenForOrder(orderKey, env.LICENSE_PRIVATE_KEY);
  await env.LICENSES.put(`license:${own}`, bundle);
  let token = own;
  let duplicate = false;
  if (claim !== null) {
    const bound = await bindClaim(env, deps, orderKey, licenseId, claim);
    duplicate = bound === "own";
    if (bound) {
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
  return { duplicate };
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
  let licenseId = await licenseIdOf(env, orderKey);
  const issued = licenseId !== null;
  if (!issued) {
    // Not issued (yet): the transaction webhook may still be retrying, and
    // Paddle never redelivers this 2xx. The licence id comes from the order,
    // so record it under the id that order would be issued with. For another
    // product's order that id is never issued and the record is harmless.
    licenseId = await licenseIdForOrder(orderKey);
    console.warn(`license-issuer: ${provider} adjustment ${adjustment.adjustmentId} for order ${adjustment.orderId} not issued yet; recorded under ${licenseId}`);
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
  // adjustment.updated overwrites the same keys with the newer status. Paddle
  // does not guarantee delivery order, so an older event arriving late (or a
  // retry) must not replace a newer record.
  const storedText = await env.LICENSES.get(`adjustment:${provider}:${adjustment.adjustmentId}`);
  if (storedText !== null && isStale(record, storedText)) {
    console.warn(`license-issuer: ${provider} adjustment ${adjustment.adjustmentId}: ignoring out-of-order event`);
    return plain(200, "Recorded");
  }
  await writeRevocation(env, provider, adjustment.adjustmentId, record);
  await noteRefundState(env, record);
  if (adjustment.revoke) console.warn(`license-issuer: licence ${licenseId} needs revoking (${adjustment.action})`);
  // One push per refund of a licence this Worker issued: not for other products'
  // orders, and not again when the same approved adjustment is redelivered.
  if (provider === "paddle" && adjustment.revoke && issued && !alreadyRevoking(storedText)) {
    await alert(env, deps, paddleRefundAlert(adjustment));
  }
  return plain(200, "Recorded");
}

// refund-state:<license_id> -> {<adjustment id>: {revoke, at}} for the decisive
// refund / chargeback events of a web order (Paddle, Lemon Squeezy). The licence
// page reads it so a refunded order's key is no longer handed out (scan F4).
// The newest decisive event wins, as in scripts/revocation-list.mjs.
const refundStateKey = (licenseId) => `refund-state:${licenseId}`;

function parseRefundState(text) {
  try {
    const value = JSON.parse(text ?? "null");
    if (value !== null && typeof value === "object" && !Array.isArray(value)) return new Map(Object.entries(value));
  } catch {
    // unreadable: treated as no refund
  }
  return new Map();
}

async function noteRefundState(env, record) {
  const key = refundStateKey(record.license_id);
  const state = parseRefundState(await env.LICENSES.get(key));
  if (record.revoke || record.reinstate) {
    state.set(record.adjustment_id, { revoke: record.revoke === true, at: String(record.occurred_at ?? record.recorded_at ?? "") });
  } else if (state.has(record.adjustment_id)) {
    state.delete(record.adjustment_id); // a newer event left this adjustment undecided
  } else {
    return;
  }
  await env.LICENSES.put(key, JSON.stringify(Object.fromEntries(state)));
}

async function isRefunded(env, licenseId) {
  if (typeof licenseId !== "string" || licenseId === "") return false;
  let last = null;
  for (const entry of parseRefundState(await env.LICENSES.get(refundStateKey(licenseId))).values()) {
    if (entry === null || typeof entry !== "object") continue;
    if (last === null || String(entry.at) >= String(last.at)) last = entry;
  }
  return last !== null && last.revoke === true;
}

function alreadyRevoking(storedText) {
  try {
    return JSON.parse(storedText ?? "null")?.revoke === true;
  } catch {
    return false;
  }
}

const TERMINAL_ADJUSTMENT_STATUSES = new Set(["approved", "rejected", "reversed"]);

// True when `incoming` is older than the stored record, or as old while the
// stored one already has a terminal status and the incoming one does not.
function isStale(incoming, storedText) {
  let stored;
  try {
    stored = JSON.parse(storedText);
  } catch {
    return false;
  }
  const a = Date.parse(incoming.occurred_at ?? "");
  const b = Date.parse(stored?.occurred_at ?? "");
  if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
  if (a !== b) return a < b;
  return TERMINAL_ADJUSTMENT_STATUSES.has(stored.status) && !TERMINAL_ADJUSTMENT_STATUSES.has(incoming.status);
}

async function webhook(provider, request, env, deps) {
  if (env.PROVIDER && env.PROVIDER !== provider) return plain(404, "Not found");
  const body = await readBody(request, MAX_WEBHOOK_BYTES);
  if (body === null) {
    console.error(`license-issuer: ${provider} webhook over ${MAX_WEBHOOK_BYTES} bytes refused (413); a sale or refund may be missing`);
    // Unauthenticated (the signature is not checked yet), so at most one push per provider a day,
    // with the marker claimed before sending (final review L4).
    const day = new Date(nowMs(deps)).toISOString().slice(0, 10);
    await alertClaimFirst(env, deps, `webhook-too-large:${provider}:${day}`, {
      title: "LocalGateKeys webhook refused",
      message: `${provider}: a webhook over ${MAX_WEBHOOK_BYTES / 1024} KiB was refused; check the provider's event log for a missing sale or refund`,
      tags: "warning",
    });
    return plain(413, "Payload too large");
  }
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
  // Every delivery that finishes issuing asks; alertOnce sends one per order (W5). A retry after a
  // delivery that bound the claim and then failed reads the claim back as its own, and still alerts
  // (final review L5), which skipping "duplicate" deliveries lost.
  if (provider === "paddle") await alertOnce(env, deps, `paddle-sale:${order.orderId}`, paddleSaleAlert(event.data));
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
  const bundle = JSON.parse(stored);
  // Refunded (Paddle / Lemon Squeezy): the key is not handed out again. /recover
  // leads here too, so it gets the same answer. 403 as for a revoked store claim.
  if (await isRefunded(env, bundle?.license?.license_id)) {
    if (wantFile) return plain(403, "Revoked");
    const support = env.SUPPORT_EMAIL ? escapeHtml(env.SUPPORT_EMAIL) : "support";
    return page(
      "Licence refunded",
      "<h1>This licence was refunded</h1>" +
        "<p>The order for this licence was refunded, so the licence is no longer valid and its key is not shown.</p>" +
        `<p>If you think this is a mistake, contact ${support} with your order number.</p>`,
      "",
      {},
      403,
    );
  }
  if (wantFile) {
    return respond(200, stored, "application/json", {
      "Content-Disposition": 'attachment; filename="LocalGateKeys-Pro.lgklicense"',
    });
  }
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
      `<p><a href="/license/${escapeHtml(token)}/file" download>Download LocalGateKeys-Pro.lgklicense</a></p>` +
      `<h2>Next steps</h2><ol>` +
      `<li>Install LocalGateKeys if you have not yet: <a href="${SITE_URL}/download">downloads for Windows, Mac and iPhone</a>.</li>` +
      `<li>Open LocalGateKeys, go to Licence, and paste the key above (or press Install in LocalGateKeys).</li>` +
      `<li>Keep this page's key or file somewhere safe. Lost it? <a href="${RECOVER_PATH}">Recover your licence</a> ` +
      `with your order number and email.</li></ol>`,
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

// Counts this attempt; returns the seconds to wait if this email + order id
// pair, the email, or the order id is over its limit, else 0. The tight limit
// is keyed by the pair, so someone who knows a buyer's email can lock the real
// order out only via the looser per-email cap, for at most one window; only
// well-formed order ids reach here (the per-IP zone rule bounds the rest). KV increments are not atomic and reads may lag between
// locations, so a burst can slip a few extra attempts in; the per-IP rule
// bounds bursts. The record expires with its window.
async function throttleRecovery(env, deps, email, orderId) {
  const limits = [
    [recoveryThrottleKey(`${email}|${orderId}`, env.LICENSE_PRIVATE_KEY), RECOVER_MAX_ATTEMPTS],
    [throttleKey("recover-email", email, env.LICENSE_PRIVATE_KEY), RECOVER_MAX_PER_EMAIL],
    [throttleKey("recover-order", orderId, env.LICENSE_PRIVATE_KEY), RECOVER_MAX_PER_ORDER],
  ];
  // Every limiter counts the attempt (no early exit), so the KV reads are the
  // same whether or not one is over its limit.
  let wait = 0;
  for (const [key, max] of limits) wait = Math.max(wait, await throttle(env, deps, key, max));
  return wait;
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
  if (!ORDER_ID.test(orderId)) return notFound();
  const wait = await throttleRecovery(env, deps, email, orderId);
  if (wait > 0) {
    return recoverForm(
      "Too many attempts. Try again in an hour, or contact support.",
      429,
      { "Retry-After": String(wait) },
    );
  }
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

// The throttle key for a client: an IPv4 address as is, an IPv6 address by its
// /64 (one subscriber usually holds a whole /64, so rotating within it is free).
function clientNetwork(ip) {
  if (!ip.includes(":")) return ip;
  const [head, tail = ""] = ip.toLowerCase().split("::");
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  if (right.length && right[right.length - 1].includes(".")) right.splice(-1, 1, "0", "0"); // embedded IPv4
  const groups = ip.includes("::")
    ? [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right]
    : left;
  return `${groups.slice(0, 4).map((g) => (g.replace(/^0+/, "") || "0")).join(":")}::/64`;
}

// Counts this claim against the client network; null if allowed, else the 429.
async function throttleStoreClaim(request, env, deps) {
  const ip = clientNetwork(request.headers.get("CF-Connecting-IP") ?? "unknown");
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

// A refund a claim proves (the client's JWS or Apple's current view): one adjustment id per
// purchase, so every repeat overwrites the same `revoke:` record.
function revokeAppStoreClaim(env, deps, originalTransactionId, revocationDate) {
  return revokeStoreClaim(
    env,
    "appstore_claims",
    originalTransactionId,
    {
      adjustmentId: `refund-${originalTransactionId}`,
      action: "refund",
      occurredAt: new Date(Number.isFinite(revocationDate) ? revocationDate : nowMs(deps)).toISOString(),
    },
    nowMs(deps),
  );
}

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
  if (tx.revocationDate !== undefined && tx.revocationDate !== null) {
    // Apple-signed proof of a refund the webhook may have missed (scan F3): record it the way
    // the Server API check below does, under the same adjustment id, so a repeat overwrites it.
    if (env.CLAIMS) await revokeAppStoreClaim(env, deps, tx.originalTransactionId, tx.revocationDate);
    else console.error("license-issuer: D1 binding CLAIMS missing; a refunded App Store claim was not recorded");
    return plain(403, "Revoked");
  }
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
      await revokeAppStoreClaim(env, deps, tx.originalTransactionId, current.revocationDate);
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
  if (purchase.purchaseState === 1) {
    // Canceled / refunded, confirmed by Google (scan F3): record it now rather than waiting for
    // the daily cron. Same adjustment id as the push and the cron, so they overwrite one record.
    if (env.CLAIMS && typeof purchase.orderId === "string" && PLAY_ORDER_ID.test(purchase.orderId)) {
      await revokePlayOrder(env, purchase.orderId, new Date(nowMs(deps)).toISOString(), nowMs(deps));
    }
    return plain(403, "Revoked");
  }
  if (purchase.purchaseState !== 0 || purchase.consumptionState !== 0) return invalid();
  // Unacknowledged purchases are auto-refunded by Google after 3 days; the app
  // acknowledges before claiming, so a 400 here makes it retry afterwards.
  if (purchase.acknowledgementState !== 1) return invalid();
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
    purchaseToken = voided.purchaseToken;
    notedOrderId = typeof voided.orderId === "string" ? voided.orderId : null;
  } else if (oneTime?.notificationType === 1 && oneTime.sku === PLAY_PRODUCT) {
    // ONE_TIME_PRODUCT_PURCHASED: only the sales alert; claims issue the licence.
    if (typeof oneTime.purchaseToken === "string") {
      await alertOnce(env, deps, `play-sale:${await sha256Hex(oneTime.purchaseToken)}`, PLAY_SOLD_ALERT);
    }
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
  // Only now: the purchase is confirmed canceled and recorded; once per order across redeliveries (W1).
  await alertOnce(env, deps, `play-refund:${purchase.orderId}`, PLAY_REFUND_ALERT);
  return plain(200, "Recorded");
}

const APPSTORE_REVOKING = new Set(["REFUND", "REVOKE"]);
const APPSTORE_REINSTATING = new Set(["REFUND_REVERSED"]);

// App Store Server Notifications V2. REFUND and REVOKE mark the purchase
// revoked and write its `revoke:` record; REFUND_REVERSED clears the flag and
// writes a reinstate record; everything else is acknowledged and ignored. A bad signature is 400 (Apple retries, then gives up).
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
  if (!appStoreEnvironmentAllowed(env, tx.environment)) return plain(200, "Ignored");
  const reinstating = APPSTORE_REINSTATING.has(note.notificationType);
  // Alerts are sent only after every check and write, once per notification (W3).
  const alertKey = `appstore:${typeof note.notificationUUID === "string" ? note.notificationUUID : `${note.notificationType}-${tx.originalTransactionId}`}`;
  if (!reinstating && !APPSTORE_REVOKING.has(note.notificationType)) {
    await alertOnce(env, deps, alertKey, appStoreAlert(note, tx));
    return plain(200, "Ignored");
  }
  if (typeof tx.originalTransactionId !== "string" || !ORDER_ID.test(tx.originalTransactionId)) return invalid();
  if (!env.CLAIMS) return plain(503, "Unavailable");
  const uuid = typeof note.notificationUUID === "string" && ORDER_ID.test(note.notificationUUID) ? note.notificationUUID : null;
  if (reinstating) {
    // Dated by when Apple signed the notice, later than the refund it reverses.
    const signed = Number.isFinite(note.signedDate) ? note.signedDate : nowMs(deps);
    await reinstateStoreClaim(
      env,
      "appstore_claims",
      tx.originalTransactionId,
      {
        adjustmentId: uuid ?? `refund_reversed-${tx.originalTransactionId}`,
        action: "refund_reversed",
        occurredAt: new Date(signed).toISOString(),
      },
      nowMs(deps),
    );
    return plain(200, "Recorded");
  }
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
  await alertOnce(env, deps, alertKey, appStoreAlert(note, tx));
  return plain(200, "Recorded");
}

const PLAY_SOLD_ALERT = { title: "LocalGateKeys Pro sold", message: "Google Play: new purchase", tags: "moneybag" };
const PLAY_REFUND_ALERT = { title: "LocalGateKeys Pro refunded", message: "Google Play: purchase voided", tags: "warning" };
// Long enough to cover any provider's redelivery window (Pub/Sub 7 days, Apple about 3 days, Paddle 3 days).
const ALERT_DEDUP_TTL_SECONDS = 14 * 24 * 3600;

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const alertsOn = (env) => Boolean(env.SALES_NTFY_TOPIC || (env.SALES_EMAIL && env.SALES_EMAIL_TO));

// Sends an alert without holding the webhook response: with a request context
// (production) it runs in ctx.waitUntil; tests without ctx await it.
// `onSent` runs only after ntfy accepted the push.
// `onFailed` runs when neither the push nor the email went out.
async function alert(env, deps, salesAlert, onSent, onFailed) {
  if (!salesAlert || !alertsOn(env)) return;
  const sending = Promise.all([
    sendSalesAlert(env, salesAlert, deps.fetch ?? fetch),
    sendSalesEmail(env, salesAlert, deps.makeEmail),
  ]).then(async ([pushed, mailed]) => {
    if (pushed || mailed) {
      if (onSent) await onSent();
    } else if (onFailed) onFailed();
  }, (error) => {
    if (onFailed) onFailed();
    throw error;
  });
  if (deps.ctx?.waitUntil) deps.ctx.waitUntil(sending);
  else await sending;
}

// Alerts once per key so provider retries do not push twice. The KV marker is
// written only after the push went through, so a failed push is sent again when
// the provider redelivers. Within one isolate a key being sent (or sent) is
// claimed synchronously, so concurrent deliveries there push once; the claim is
// released if the alert fails. KV is not atomic: two truly simultaneous
// deliveries in different isolates can still both push.
const alertsInFlight = new WeakMap(); // per KV binding object (one per isolate in production)
const MAX_ALERT_CLAIMS = 1000;
function isolateClaims(env) {
  let claims = alertsInFlight.get(env.LICENSES);
  if (!claims || claims.size >= MAX_ALERT_CLAIMS) {
    claims = new Set();
    alertsInFlight.set(env.LICENSES, claims);
  }
  return claims;
}
async function alertOnce(env, deps, key, salesAlert) {
  if (!salesAlert || !alertsOn(env)) return;
  const claims = isolateClaims(env);
  if (claims.has(key)) return;
  claims.add(key);
  const marker = `alerted:${key}`;
  try {
    if ((await env.LICENSES.get(marker)) !== null) return;
  } catch (error) {
    console.warn(`license-issuer: alert dedup unavailable: ${error}`);
  }
  await alert(env, deps, salesAlert, async () => {
    try {
      await env.LICENSES.put(marker, "1", { expirationTtl: ALERT_DEDUP_TTL_SECONDS });
    } catch (error) {
      console.warn(`license-issuer: alert dedup unavailable: ${error}`);
    }
  }, () => claims.delete(key));
}

// For alerts anyone can trigger without a signature (an oversize webhook): the
// key is claimed before sending, so a burst cannot push once per request. First
// a synchronous per-isolate claim (kept even if the push fails), then the KV
// marker, written before the push (a rare lost alert is the accepted cost).
// Across locations KV lag can still let a few through, never one per request.
async function alertClaimFirst(env, deps, key, salesAlert) {
  if (!salesAlert || !alertsOn(env)) return;
  const claimed = isolateClaims(env);
  if (claimed.has(key)) return;
  claimed.add(key);
  const marker = `alerted:${key}`;
  try {
    if ((await env.LICENSES.get(marker)) !== null) return;
    await env.LICENSES.put(marker, "1", { expirationTtl: ALERT_DEDUP_TTL_SECONDS });
  } catch (error) {
    console.warn(`license-issuer: alert dedup unavailable, alert not sent: ${error}`);
    return;
  }
  await alert(env, deps, salesAlert);
}

// Owner-only: sends one test push through the sales-alert path, to check ntfy
// accepts pushes from the Worker. Off unless the secret ALERT_TEST_TOKEN is set
// (at least 32 characters); the caller sends it as "Authorization: Bearer <token>".
async function testAlert(request, env, deps) {
  const token = env.ALERT_TEST_TOKEN;
  if (typeof token !== "string" || token.length < 32 || !alertsOn(env)) return plain(404, "Not found");
  const given = new TextEncoder().encode(request.headers.get("Authorization") ?? "");
  const want = new TextEncoder().encode(`Bearer ${token}`);
  const [a, b] = await Promise.all([crypto.subtle.digest("SHA-256", given), crypto.subtle.digest("SHA-256", want)]);
  const x = new Uint8Array(a), y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  if (diff !== 0) return plain(404, "Not found");
  const test = { title: "LocalGateKeys test alert", message: "Sent by the licence Worker", tags: "test_tube" };
  const [pushed, mailed] = await Promise.all([sendSalesAlert(env, test, deps.fetch ?? fetch), sendSalesEmail(env, test, deps.makeEmail)]);
  return plain(pushed || mailed ? 200 : 502, `ntfy: ${pushed ? "sent" : "failed"}, email: ${mailed ? "sent" : "failed or off"}`);
}

// The daily Play voided-purchases backstop. A run that stops early (backlog
// past its page or time budget) saves where it stopped and the next run goes on
// from there; the owner gets one push per backlog (keyed by its start time).
export async function runVoidedSync(env, deps = {}) {
  const fetchImpl = deps.fetch ?? fetch;
  try {
    return await syncVoided(env, fetchImpl, nowMs(deps), {
      ...(deps.voided ?? {}),
      onIncomplete: (resume) =>
        alertOnce(env, { ...deps, ctx: undefined }, `play-voided-incomplete:${resume.start}`, {
          title: "LocalGateKeys Play refund check incomplete",
          message: "Google Play: more voided purchases than one daily run handles; the next run continues",
          tags: "warning",
        }),
    });
  } catch (error) {
    console.error(`license-issuer: Play voided-purchases sync failed: ${error.message}`);
    return null;
  }
}

// Any unhandled exception (D1/KV/fetch outage) answers 503 with Retry-After
// instead of Cloudflare's generic error page (L1); providers retry webhooks.
export async function handle(request, env, deps = {}) {
  try {
    return await route(request, env, deps);
  } catch (error) {
    console.error(`license-issuer: unhandled error: ${error?.stack ?? error}`);
    return respond(503, "Temporarily unavailable. Please try again in a minute.\n", "text/plain; charset=utf-8", { "Retry-After": "30" });
  }
}

async function route(request, env, deps = {}) {
  const url = new URL(request.url);
  const { pathname } = url;
  if (request.method === "POST" && pathname === "/appstore/claim") return appStoreClaim(request, env, deps);
  if (request.method === "POST" && pathname === "/admin/test-alert") return testAlert(request, env, deps);
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
  fetch(request, env, ctx) {
    return handle(request, env, { ctx });
  },
  // Cron trigger (wrangler.jsonc): the Play voided-purchases backstop.
  scheduled(controller, env, ctx) {
    ctx.waitUntil(runVoidedSync(env, { fetch }));
  },
};
