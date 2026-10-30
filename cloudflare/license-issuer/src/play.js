// Google Play: purchase lookups with the Play Developer API. Play purchase
// tokens cannot be checked offline, so the Worker signs an OAuth JWT (RS256)
// with the service account in the secret PLAY_SERVICE_ACCOUNT_JSON and asks
// Google. Access tokens and purchase tokens are never logged.

import { toBase64Url } from "./sign.js";
import { revokeStoreClaim } from "./store-claims.js";

export const PLAY_PACKAGE = "app.localgatekeys.android";
export const PLAY_PRODUCT = "pro_unlimited";
const SCOPE = "https://www.googleapis.com/auth/androidpublisher";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
export const PLAY_API = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${PLAY_PACKAGE}`;
const encoder = new TextEncoder();

// `invalid`: Google does not know the token (4xx). `unavailable`: Google, the
// network or the configuration failed; the app retries later (503).
export class PlayError extends Error {
  constructor(code) {
    super(`play: ${code}`);
    this.code = code;
  }
}

// Cached per env object (one per isolate) until a minute before expiry.
const tokenCache = new WeakMap();

function serviceAccount(env) {
  try {
    const account = JSON.parse(env.PLAY_SERVICE_ACCOUNT_JSON ?? "");
    if (typeof account.client_email === "string" && typeof account.private_key === "string") return account;
  } catch {
    // fall through
  }
  console.error("license-issuer: PLAY_SERVICE_ACCOUNT_JSON is missing or malformed; Play claims are unavailable");
  throw new PlayError("unavailable");
}

function pemToDer(pem) {
  const body = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

const b64urlJson = (value) => toBase64Url(encoder.encode(JSON.stringify(value)));

async function call(fetchImpl, url, init) {
  let response;
  try {
    response = await fetchImpl(url, init);
  } catch {
    throw new PlayError("unavailable");
  }
  if (response.ok) {
    try {
      return await response.json();
    } catch {
      throw new PlayError("unavailable");
    }
  }
  // 401/403 mean our credentials are wrong, 408/429/5xx are transient: retry later.
  if ([401, 403, 408, 429].includes(response.status) || response.status >= 500) {
    if (response.status === 401 || response.status === 403) {
      console.error(`license-issuer: Google refused the Play service account (${response.status})`);
    }
    throw new PlayError("unavailable");
  }
  throw new PlayError("invalid");
}

// An OAuth access token for the Play Developer API.
export async function playAccessToken(env, fetchImpl, now = Date.now()) {
  const cached = tokenCache.get(env);
  if (cached && cached.expires > now) return cached.token;
  const account = serviceAccount(env);
  let key;
  try {
    key = await crypto.subtle.importKey("pkcs8", pemToDer(account.private_key), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  } catch {
    console.error("license-issuer: the Play service account key does not import");
    throw new PlayError("unavailable");
  }
  const iat = Math.floor(now / 1000);
  const input = `${b64urlJson({ alg: "RS256", typ: "JWT" })}.${b64urlJson({ iss: account.client_email, scope: SCOPE, aud: TOKEN_URL, iat, exp: iat + 3600 })}`;
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, encoder.encode(input)));
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: `${input}.${toBase64Url(sig)}`,
  });
  let result;
  try {
    result = await call(fetchImpl, TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
  } catch {
    throw new PlayError("unavailable"); // even a 4xx here is our problem, not the buyer's
  }
  if (typeof result.access_token !== "string") throw new PlayError("unavailable");
  const lifetime = Number.isFinite(result.expires_in) ? result.expires_in : 3600;
  tokenCache.set(env, { token: result.access_token, expires: now + Math.max(0, lifetime - 60) * 1000 });
  return result.access_token;
}

// Purchase tokens are opaque; this keeps them to URL-safe characters.
export const PURCHASE_TOKEN = /^[A-Za-z0-9._-]{1,1024}$/;

// purchases.products.get for pro_unlimited.
export async function getPlayPurchase(env, token, fetchImpl, now = Date.now()) {
  if (!PURCHASE_TOKEN.test(token)) throw new PlayError("invalid");
  const accessToken = await playAccessToken(env, fetchImpl, now);
  const purchase = await call(fetchImpl, `${PLAY_API}/purchases/products/${PLAY_PRODUCT}/tokens/${encodeURIComponent(token)}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return {
    orderId: purchase.orderId,
    purchaseState: purchase.purchaseState,
    consumptionState: purchase.consumptionState,
    purchaseType: purchase.purchaseType,
    acknowledgementState: purchase.acknowledgementState,
  };
}

// --- Refunds -------------------------------------------------------------------

const GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS = new Set(["accounts.google.com", "https://accounts.google.com"]);
const CLOCK_SKEW_SECONDS = 300;

function decodeSegment(segment) {
  const b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
}

const decodeJson = (segment) => JSON.parse(new TextDecoder().decode(decodeSegment(segment)));

// Verifies the Google-signed OIDC token Pub/Sub puts on a push
// ("Authorization: Bearer <jwt>"): RS256 with a key from Google's JWKS, issuer
// accounts.google.com, audience `audience`, not expired, and minted for the
// push subscription's own service account `account` (verified email). Anyone
// can get a Google ID token for any audience, so the account check is what ties
// the push to our subscription. An empty `account` refuses every token.
// Returns the claims or throws.
export async function verifyGoogleOidc(authHeader, audience, account, fetchImpl, now = Date.now()) {
  const match = /^Bearer ([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(authHeader ?? "");
  if (!match || typeof audience !== "string" || audience === "") throw new Error("oidc: bad header");
  if (typeof account !== "string" || account.trim() === "") throw new Error("oidc: no push account");
  const header = decodeJson(match[1]);
  const claims = decodeJson(match[2]);
  if (header.alg !== "RS256" || typeof header.kid !== "string") throw new Error("oidc: bad alg");
  const jwks = await (await fetchImpl(GOOGLE_JWKS)).json();
  const jwk = (jwks.keys ?? []).find((k) => k.kid === header.kid && k.kty === "RSA");
  if (!jwk) throw new Error("oidc: unknown key");
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const signed = encoder.encode(`${match[1]}.${match[2]}`);
  if (!(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decodeSegment(match[3]), signed))) {
    throw new Error("oidc: bad signature");
  }
  const nowSec = Math.floor(now / 1000);
  if (!GOOGLE_ISSUERS.has(claims.iss)) throw new Error("oidc: issuer");
  if (claims.aud !== audience) throw new Error("oidc: audience");
  if (!Number.isFinite(claims.exp) || claims.exp + CLOCK_SKEW_SECONDS < nowSec) throw new Error("oidc: expired");
  if (Number.isFinite(claims.iat) && claims.iat - CLOCK_SKEW_SECONDS > nowSec) throw new Error("oidc: future");
  if (claims.email !== account.trim() || claims.email_verified !== true) throw new Error("oidc: account");
  return claims;
}

export const VOIDED_CURSOR_KEY = "play:voided:cursor";
export const PLAY_ORDER_ID = /^[A-Za-z0-9._-]{1,64}$/;
// The Voided Purchases API looks back at most 30 days.
const VOIDED_LOOKBACK_MS = 30 * 24 * 3600 * 1000;
const VOIDED_MAX_PAGES = 20;

// One adjustment id per order, so a push and the cron overwrite the same record.
export function revokePlayOrder(env, orderId, occurredAt, now = Date.now()) {
  return revokeStoreClaim(env, "play_claims", orderId, { adjustmentId: `void-${orderId}`, action: "refund", occurredAt }, now);
}

// Daily backstop for missed pushes: reads voided purchases since the stored
// cursor, revokes each order (claimed or not), and advances the cursor to the
// newest voided time seen. Returns the number of voided purchases handled.
export async function syncVoided(env, fetchImpl, now = Date.now()) {
  const stored = Number(await env.LICENSES.get(VOIDED_CURSOR_KEY));
  const start = Math.max(Number.isFinite(stored) && stored > 0 ? stored : 0, now - VOIDED_LOOKBACK_MS + 60000);
  const accessToken = await playAccessToken(env, fetchImpl, now);
  let newest = start;
  let handled = 0;
  let pageToken = null;
  for (let page = 0; page < VOIDED_MAX_PAGES; page++) {
    const params = new URLSearchParams({ startTime: String(start), type: "0" });
    if (pageToken) params.set("token", pageToken);
    const result = await call(fetchImpl, `${PLAY_API}/purchases/voidedpurchases?${params}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    for (const voided of result.voidedPurchases ?? []) {
      if (typeof voided.orderId !== "string" || !PLAY_ORDER_ID.test(voided.orderId)) continue;
      const at = Number(voided.voidedTimeMillis);
      await revokePlayOrder(env, voided.orderId, new Date(Number.isFinite(at) ? at : now).toISOString(), now);
      if (Number.isFinite(at) && at > newest) newest = at;
      handled += 1;
    }
    pageToken = result.tokenPagination?.nextPageToken ?? null;
    if (!pageToken) break;
  }
  await env.LICENSES.put(VOIDED_CURSOR_KEY, String(newest));
  return handled;
}
