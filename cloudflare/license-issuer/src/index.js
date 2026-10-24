// LocalGateKeys licence issuer: payment webhooks in, signed Pro licences out.
//
//   POST /webhooks/lemonsqueezy | /webhooks/paddle   -> issue + store licence
//   GET  /license/<token>                            -> HTML page with LGK1- key
//   GET  /license/<token>/file                       -> .lgklicense download
//   GET  /recover, POST /recover                     -> find a licence by order id + email
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
import { buildLicense, encodePaste, fallbackTokenForOrder, issueBundle, licenseIdForOrder } from "./sign.js";

const PENDING_GIVE_UP_SECONDS = 10 * 60;
// KV caches reads at the edge, "not found" included, for 60 s by default. The
// pending page polls before the webhook lands, so ask for the shortest cache
// KV allows (30 s) to show a fresh licence sooner.
const LICENSE_CACHE_TTL_SECONDS = 30;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_FORM_BYTES = 4 * 1024;
const TOKEN_PATH = /^\/license\/([A-Za-z0-9_-]{43})(\/file)?$/;
const RECOVER_PATH = "/recover";
const ORDER_ID = /^[A-Za-z0-9_-]{1,64}$/;
const PAGE_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
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
      `textarea{width:100%;height:9rem;font:12px monospace}</style></head><body>${inner}</body></html>`,
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
//   claim:<token>                        -> the order key a browser claim is bound to
//   license:<token>                      -> signed licence bundle (JSON), under the order's
//                                           own token and, if it won it, the claim
//   adjustment:<provider>:<id>           -> refund / chargeback record (JSON, also as metadata)
//   revoke:<license_id>:<adjustment id>  -> the same record, listed by the operator to revoke
//
// KV has no compare-and-set, so the claim binding is written before the
// licence and read back; an order that bound the claim first (as far as KV
// shows it) keeps it and a later order uses its own token. Two orders that both
// see an unbound claim within KV's propagation delay can still both write the
// claim's page (the last write shows); each keeps its licence under its own
// token, which /recover finds. Strict exclusion would need a Durable Object or D1.

// Returns the claim if this order may use it, else null.
async function bindClaim(env, orderKey, claim) {
  if (claim === null) return null;
  const bindingKey = `claim:${claim}`;
  const bound = await env.LICENSES.get(bindingKey);
  if (bound !== null) return bound === orderKey ? claim : null;
  // Licences issued before claims were bound: a stored licence means "used".
  if ((await env.LICENSES.get(`license:${claim}`)) !== null) return null;
  await env.LICENSES.put(bindingKey, orderKey);
  return (await env.LICENSES.get(bindingKey)) === orderKey ? claim : null;
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
  // this Worker can compute; recovery (POST /recover) leads there, so a lost
  // claim race never loses the licence. A claim this order won is an alias.
  const own = await fallbackTokenForOrder(orderKey, env.LICENSE_PRIVATE_KEY);
  await env.LICENSES.put(`license:${own}`, bundle);
  let token = own;
  if ((await bindClaim(env, orderKey, claim)) !== null) {
    await env.LICENSES.put(`license:${claim}`, bundle);
    // Read the binding again: if another order took the claim meanwhile, point
    // this order at its own token rather than at a page the other order owns.
    if ((await env.LICENSES.get(`claim:${claim}`)) === orderKey) token = claim;
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
  const value = JSON.stringify(record);
  // The record doubles as metadata so `wrangler kv key list` shows it (< 1 KiB).
  // adjustment.updated overwrites the same keys with the newer status.
  await env.LICENSES.put(`adjustment:${provider}:${adjustment.adjustmentId}`, value, { metadata: record });
  await env.LICENSES.put(`revoke:${licenseId}:${adjustment.adjustmentId}`, value, { metadata: record });
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
  return page(
    "Your LocalGateKeys Pro licence",
    `<h1>Your LocalGateKeys Pro licence</h1>` +
      `<p>Licensed to ${holder}.</p>` +
      `<p>Paste this key into LocalGateKeys, or download the file and open it there.</p>` +
      `<textarea readonly>${escapeHtml(encodePaste(bundle))}</textarea>` +
      `<p><a href="/license/${escapeHtml(token)}/file" download>Download LocalGateKeys-Pro.lgklicense</a></p>`,
  );
}

// Lost the licence page (closed the tab, claim bound to someone else's order)?
// The order id from the receipt plus the email it was bought with lead back to
// it. Every failure gives the same answer, so the form says nothing about which
// part was wrong. The form posts to itself only.
const RECOVER_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
};

function recoverForm(message = "", status = 200) {
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
    RECOVER_HEADERS,
    status,
  );
}

function providersFor(env, orderId) {
  if (env.PROVIDER) return [env.PROVIDER];
  return orderId.startsWith("txn_") ? ["paddle"] : ["lemonsqueezy", "paddle"];
}

async function recover(request, env) {
  const notFound = () =>
    recoverForm("No licence matches that order number and email. Check both, or contact support.", 404);
  const body = await readBody(request, MAX_FORM_BYTES);
  if (body === null) return plain(413, "Payload too large");
  const form = new URLSearchParams(body);
  const orderId = (form.get("order") ?? "").trim();
  const email = (form.get("email") ?? "").trim().toLowerCase();
  if (!ORDER_ID.test(orderId) || !email.includes("@")) return notFound();
  for (const provider of providersFor(env, orderId)) {
    const orderKey = `order:${provider}:${orderId}`;
    const indexed = await env.LICENSES.get(orderKey);
    if (indexed === null) continue;
    // The order's own token first (always its own licence); orders issued
    // before own tokens existed have only the indexed one.
    const own = await fallbackTokenForOrder(orderKey, env.LICENSE_PRIVATE_KEY);
    for (const token of [own, indexed]) {
      const stored = await env.LICENSES.get(`license:${token}`);
      if (stored === null) continue;
      const holder = String(JSON.parse(stored)?.license?.email ?? "").trim().toLowerCase();
      if (holder === email) {
        return respond(303, "", "text/plain; charset=utf-8", { Location: `/license/${token}` });
      }
      break;
    }
  }
  return notFound();
}

export async function handle(request, env, deps = {}) {
  const url = new URL(request.url);
  const { pathname } = url;
  if (request.method === "POST" && (pathname === "/webhooks/lemonsqueezy" || pathname === "/webhooks/paddle")) {
    return webhook(pathname.slice("/webhooks/".length), request, env, deps);
  }
  if (pathname === RECOVER_PATH) {
    if (request.method === "POST") return recover(request, env);
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
};
