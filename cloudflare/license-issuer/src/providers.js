// Payment-provider webhook verification and parsing.

const encoder = new TextEncoder();
const CLAIM = /^[A-Za-z0-9_-]{43}$/;
const PADDLE_TOLERANCE_SECONDS = 300;

function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) return null;
  return Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));
}

// crypto.subtle.verify compares the MAC in constant time.
async function hmacMatches(secret, message, hexSignature) {
  const sig = hexToBytes(hexSignature);
  if (sig === null || !secret) return false;
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "verify",
  ]);
  return crypto.subtle.verify("HMAC", key, sig, encoder.encode(message));
}

export function validClaim(value) {
  return typeof value === "string" && CLAIM.test(value) ? value : null;
}

// The product ids that sell Pro. An unset or empty PRODUCT_IDS is a
// configuration error, never "every product": the merchant account may sell
// other things, and none of them may mint a Pro licence.
export function configuredProductIds(env) {
  return String(env?.PRODUCT_IDS ?? "")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
}

// Fails closed: with no configured products nothing is allowed.
function productAllowed(env, ids) {
  const wanted = configuredProductIds(env);
  if (wanted.length === 0) return false;
  return ids.some((id) => id != null && wanted.includes(String(id)));
}

export async function verifyLemonSqueezy(request, body, env) {
  return hmacMatches(env.WEBHOOK_SECRET, body, request.headers.get("X-Signature") ?? "");
}

export async function verifyPaddle(request, body, env, nowMs) {
  const header = request.headers.get("Paddle-Signature") ?? "";
  let ts = null;
  const hashes = [];
  for (const part of header.split(";")) {
    const [k, v] = part.split("=", 2);
    if (k?.trim() === "ts") ts = v?.trim();
    if (k?.trim() === "h1" && v) hashes.push(v.trim());
  }
  if (!ts || !/^[0-9]{1,12}$/.test(ts)) return false;
  if (Math.abs(nowMs / 1000 - Number(ts)) > PADDLE_TOLERANCE_SECONDS) return false;
  for (const h1 of hashes) {
    if (await hmacMatches(env.WEBHOOK_SECRET, `${ts}:${body}`, h1)) return true;
  }
  return false;
}

// Returns null to ignore the event, else { orderId, name, email, claim }.
export function parseLemonSqueezy(event, env = {}) {
  if (event?.meta?.event_name !== "order_created") return null;
  const attrs = event?.data?.attributes;
  if (attrs?.status !== "paid" || event.data.id == null) return null;
  if (event.meta.test_mode === true && env.ALLOW_TEST_MODE !== "1") return null;
  if (!productAllowed(env, [attrs.first_order_item?.product_id])) return null;
  const email = typeof attrs.user_email === "string" ? attrs.user_email.trim() : "";
  // A paid order we cannot deliver must not vanish: throw so the provider retries.
  if (!email.includes("@")) throw new Error("paid Lemon Squeezy order has no usable email");
  const name = typeof attrs.user_name === "string" && attrs.user_name.trim() ? attrs.user_name.trim() : email;
  return { orderId: String(event.data.id), name, email, claim: validClaim(event?.meta?.custom_data?.lgk_claim) };
}

// Only a checkout opened by Paddle.js on our /buy page (origin "web") carries a
// claim made in the buyer's browser. Transactions created through the API, the
// dashboard or a subscription renewal may carry custom data someone else chose,
// so their claim is ignored and the licence goes to a token only the Worker
// knows. Paddle always sends `origin`; an absent field (hand-made test events)
// is treated as web.
const CLAIM_ORIGINS = new Set(["web"]);

function paddleClaim(data) {
  if (data.origin !== undefined && !CLAIM_ORIGINS.has(data.origin)) return null;
  return validClaim(data?.custom_data?.lgk_claim);
}

// Paddle omits the email; returns { orderId, customerId, claim } or null.
export function parsePaddle(event, env = {}) {
  if (event?.event_type !== "transaction.completed") return null;
  const data = event.data;
  if (!data || data.id == null || typeof data.customer_id !== "string") return null;
  const items = Array.isArray(data.items) ? data.items : [];
  if (!productAllowed(env, items.map((i) => i?.price?.product_id))) return null;
  return { orderId: String(data.id), customerId: data.customer_id, claim: paddleClaim(data) };
}

const ID = /^[A-Za-z0-9_-]{1,64}$/;
const text = (value) => (typeof value === "string" ? value : null);

// Refunds and chargebacks, for revocation. Returns null to ignore the event,
// else { orderId, adjustmentId, action, status, type, occurredAt, revoke, reinstate }.
// `revoke` marks an adjustment that takes the whole payment back; `reinstate`
// one that gives it back (a reversed chargeback, a rejected or reversed refund).
// Partial refunds and chargeback warnings are recorded with neither, for review.
export function parsePaddleAdjustment(event) {
  if (event?.event_type !== "adjustment.created" && event?.event_type !== "adjustment.updated") return null;
  const data = event.data;
  if (!data || !ID.test(String(data.id ?? "")) || !ID.test(String(data.transaction_id ?? ""))) return null;
  const action = text(data.action);
  const status = text(data.status);
  const type = text(data.type);
  const takesBack = action === "refund" || action === "chargeback";
  const revoke = takesBack && status === "approved" && type !== "partial";
  const reinstate = action === "chargeback_reverse" || (takesBack && (status === "rejected" || status === "reversed"));
  return {
    orderId: String(data.transaction_id),
    adjustmentId: String(data.id),
    action,
    status,
    type,
    occurredAt: text(event.occurred_at) ?? text(data.updated_at) ?? text(data.created_at),
    revoke,
    reinstate,
  };
}

// Lemon Squeezy sends order_refunded with the order itself; status is
// "refunded" (full) or "partial_refund".
export function parseLemonSqueezyRefund(event) {
  if (event?.meta?.event_name !== "order_refunded") return null;
  const id = String(event?.data?.id ?? "");
  if (!ID.test(id)) return null;
  const status = text(event.data.attributes?.status);
  return {
    orderId: id,
    adjustmentId: `refund-${id}`,
    action: "refund",
    status,
    type: status === "refunded" ? "full" : "partial",
    occurredAt: text(event.data.attributes?.refunded_at) ?? text(event.data.attributes?.updated_at),
    revoke: status === "refunded",
    reinstate: false,
  };
}

export async function fetchPaddleCustomer(customerId, env, fetchImpl) {
  const response = await fetchImpl(`https://api.paddle.com/customers/${encodeURIComponent(customerId)}`, {
    headers: { Authorization: `Bearer ${env.PADDLE_API_KEY}` },
  });
  if (!response.ok) throw new Error(`paddle customer lookup failed: ${response.status}`);
  const customer = (await response.json())?.data;
  const email = typeof customer?.email === "string" ? customer.email.trim() : "";
  if (!email.includes("@")) throw new Error("paddle customer has no email");
  const name = typeof customer.name === "string" && customer.name.trim() ? customer.name.trim() : email;
  return { name, email };
}
