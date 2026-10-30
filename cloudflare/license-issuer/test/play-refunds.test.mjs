// Google Play refunds: Real-time Developer Notifications pushed by Pub/Sub to
// POST /webhooks/play (Google OIDC token checked), and the daily Voided
// Purchases backstop (syncVoided, run by the cron trigger).
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import worker, { handle } from "../src/index.js";
import { VOIDED_CURSOR_KEY, syncVoided } from "../src/play.js";
import { PURCHASE_URL, SERVICE_ACCOUNT, fakeGoogle, purchased } from "./fake-google.mjs";
import { NOW, makeStoreEnv, postJson, revokeKeys, verifyLicence } from "./store-helpers.mjs";

const AUDIENCE = "https://licenses.localgatekeys.app/webhooks/play";
const PUSH_ACCOUNT = "pubsub-push@example.iam.gserviceaccount.com";
const VOIDED_URL = PURCHASE_URL.replace("/products/pro_unlimited/tokens/", "/voidedpurchases?");
const google = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const stranger = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const JWK = { ...google.publicKey.export({ format: "jwk" }), kid: "google-kid-1", alg: "RS256", use: "sig" };

const b64url = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

function oidcToken({ aud = AUDIENCE, iss = "https://accounts.google.com", key = google.privateKey, exp, email = PUSH_ACCOUNT, emailVerified = true } = {}) {
  const now = Math.floor(NOW / 1000);
  const input = `${b64url({ alg: "RS256", kid: "google-kid-1", typ: "JWT" })}.${b64url({
    iss,
    aud,
    iat: now,
    exp: exp ?? now + 3600,
    email,
    email_verified: emailVerified,
  })}`;
  return `${input}.${crypto.sign("sha256", Buffer.from(input), key).toString("base64url")}`;
}

// Google's endpoints: OAuth + purchases (fake-google.mjs), JWKS and voided purchases.
function googleWith(purchases, voidedPages = []) {
  const fetchImpl = fakeGoogle(purchases);
  fetchImpl.fallback = async (url) => {
    if (url === "https://www.googleapis.com/oauth2/v3/certs") return Response.json({ keys: [JWK] });
    if (url.startsWith(VOIDED_URL)) {
      const params = new URL(url).searchParams;
      fetchImpl.voidedQueries = [...(fetchImpl.voidedQueries ?? []), Object.fromEntries(params)];
      const page = voidedPages[Number(params.get("token") ?? 0)];
      return Response.json(page ?? {});
    }
    return new Response("{}", { status: 404 });
  };
  return fetchImpl;
}

const playEnv = () => makeStoreEnv({ PLAY_SERVICE_ACCOUNT_JSON: SERVICE_ACCOUNT, PLAY_PUSH_AUDIENCE: AUDIENCE, PLAY_PUSH_SERVICE_ACCOUNT: PUSH_ACCOUNT });

function push(env, fetchImpl, notification, token = oidcToken()) {
  const data = Buffer.from(JSON.stringify({ version: "1.0", packageName: "app.localgatekeys.android", eventTimeMillis: String(NOW), ...notification })).toString("base64");
  const body = { message: { data, messageId: "m-1", publishTime: "2026-10-29T12:00:00Z" }, subscription: "projects/p/subscriptions/s" };
  return handle(postJson("/webhooks/play", body, { Authorization: `Bearer ${token}` }), env, { now: NOW, fetch: fetchImpl });
}

async function claim(env, fetchImpl, purchaseToken = "tok-1") {
  const r = await handle(postJson("/play/claim", { purchaseToken, productId: "pro_unlimited" }), env, { now: NOW, fetch: fetchImpl });
  return r.status === 200 ? verifyLicence((await r.json()).licence) : r.status;
}

const canceled = (purchaseToken = "tok-1") => ({ oneTimeProductNotification: { version: "1.0", notificationType: 2, purchaseToken, sku: "pro_unlimited" } });

test("canceled_notification_revokes", async () => {
  const env = playEnv();
  const order = purchased();
  const fetchImpl = googleWith({ "tok-1": order });
  const lic = await claim(env, fetchImpl);
  order.purchaseState = 1; // Google now reports it canceled
  const r = await push(env, fetchImpl, canceled());
  assert.equal(r.status, 200);
  assert.deepEqual(revokeKeys(env), [`revoke:${lic.license_id}:void-GPA.3300-1111-2222-33333`]);
  assert.equal(env.LICENSES.meta.get(`revoke:${lic.license_id}:void-GPA.3300-1111-2222-33333`).provider, "play");
  assert.equal(await claim(env, fetchImpl), 403);
  // Purchased notifications (type 1) and test pings are acknowledged and ignored.
  const fresh = playEnv();
  const other = googleWith({ "tok-1": purchased() });
  await claim(fresh, other);
  assert.equal((await push(fresh, other, { oneTimeProductNotification: { notificationType: 1, purchaseToken: "tok-1", sku: "pro_unlimited" } })).status, 200);
  assert.equal((await push(fresh, other, { testNotification: { version: "1.0" } })).status, 200);
  assert.deepEqual(revokeKeys(fresh), []);
});

test("bad_oidc_401", async () => {
  const env = playEnv();
  const fetchImpl = googleWith({ "tok-1": purchased() });
  await claim(env, fetchImpl);
  for (const token of [oidcToken({ key: stranger.privateKey }), oidcToken({ iss: "https://evil.example" }), oidcToken({ exp: Math.floor(NOW / 1000) - 3600 }), "garbage"]) {
    assert.equal((await push(env, fetchImpl, canceled(), token)).status, 401);
  }
  const bare = await handle(postJson("/webhooks/play", { message: {} }), env, { now: NOW, fetch: fetchImpl });
  assert.equal(bare.status, 401);
  assert.deepEqual(revokeKeys(env), []);
});

test("wrong_audience_401", async () => {
  const env = playEnv();
  const fetchImpl = googleWith({ "tok-1": purchased() });
  assert.equal((await push(env, fetchImpl, canceled(), oidcToken({ aud: "https://other.example/push" }))).status, 401);
  // No audience configured: every push is refused.
  const unset = { ...playEnv(), PLAY_PUSH_AUDIENCE: "" };
  assert.equal((await push(unset, fetchImpl, canceled())).status, 401);
});

test("voided_cron_revokes_and_advances_cursor", async () => {
  const env = playEnv();
  const fetchImpl = googleWith({ "tok-1": purchased() }, [
    { voidedPurchases: [{ orderId: "GPA.3300-1111-2222-33333", purchaseToken: "tok-1", voidedTimeMillis: String(NOW - 5000) }], tokenPagination: { nextPageToken: "1" } },
    { voidedPurchases: [{ orderId: "GPA.9999-0000", purchaseToken: "tok-9", voidedTimeMillis: String(NOW - 1000) }] },
  ]);
  const lic = await claim(env, fetchImpl);
  assert.equal(await syncVoided(env, fetchImpl, NOW), 2);
  assert.deepEqual(revokeKeys(env), [`revoke:${lic.license_id}:void-GPA.3300-1111-2222-33333`]);
  assert.equal(env.LICENSES.data.get(VOIDED_CURSOR_KEY), String(NOW - 1000));
  // The first run looks back 30 days at most; the next run starts at the cursor.
  assert.ok(Number(fetchImpl.voidedQueries[0].startTime) >= NOW - 30 * 24 * 3600 * 1000);
  await syncVoided(env, fetchImpl, NOW + 86400000);
  assert.equal(fetchImpl.voidedQueries.at(-2).startTime, String(NOW - 1000));

  // The cron trigger runs the same sync (default export `scheduled`).
  const waits = [];
  const cronEnv = playEnv();
  const realFetch = globalThis.fetch;
  globalThis.fetch = googleWith({}, [{ voidedPurchases: [{ orderId: "GPA.cron-1", voidedTimeMillis: String(Date.now() - 1000) }] }]);
  try {
    worker.scheduled({ cron: "0 4 * * *" }, cronEnv, { waitUntil: (p) => waits.push(p) });
    await Promise.all(waits);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(cronEnv.CLAIMS.store.play_claims.get("GPA.cron-1").revoked, 1);
});

test("voided_unclaimed_marks_row_revoked", async () => {
  const env = playEnv();
  const fetchImpl = googleWith({ "tok-1": purchased() }, [
    { voidedPurchases: [{ orderId: "GPA.3300-1111-2222-33333", purchaseToken: "tok-1", voidedTimeMillis: String(NOW - 5000) }] },
  ]);
  assert.equal(await syncVoided(env, fetchImpl, NOW), 1);
  assert.deepEqual(revokeKeys(env), []);
  const row = env.CLAIMS.store.play_claims.get("GPA.3300-1111-2222-33333");
  assert.equal(row.revoked, 1);
  assert.equal(row.licence_id, null);
  assert.equal(await claim(env, fetchImpl), 403, "a later claim is refused");
});

test("forged_push_account_401", async () => {
  const env = playEnv();
  const fetchImpl = googleWith({ "tok-1": purchased({ purchaseState: 1 }) });
  // Google-signed tokens for our audience, but not minted for our push account.
  for (const token of [
    oidcToken({ email: "attacker@evil-project.iam.gserviceaccount.com" }),
    oidcToken({ emailVerified: false }),
    oidcToken({ email: null }),
  ]) {
    assert.equal((await push(env, fetchImpl, canceled(), token)).status, 401);
  }
  assert.equal(env.CLAIMS.store.play_claims.size, 0);
});

test("missing_push_account_var_401", async () => {
  const fetchImpl = googleWith({ "tok-1": purchased({ purchaseState: 1 }) });
  for (const value of ["", "  ", undefined]) {
    const env = { ...playEnv(), PLAY_PUSH_SERVICE_ACCOUNT: value };
    assert.equal((await push(env, fetchImpl, canceled())).status, 401);
    assert.equal(env.CLAIMS.store.play_claims.size, 0);
  }
});

test("voided_push_unconfirmed_not_revoked", async () => {
  const env = playEnv();
  const order = purchased();
  const fetchImpl = googleWith({ "tok-1": order });
  const lic = await claim(env, fetchImpl);
  const voided = (extra) => ({
    voidedPurchaseNotification: { purchaseToken: "tok-1", orderId: order.orderId, productType: 2, refundType: 1, ...extra },
  });
  // Google still reports the purchase as purchased: nothing is revoked.
  assert.equal((await push(env, fetchImpl, voided())).status, 200);
  // An order id from the body alone (no token, unknown token, or another order) is not trusted.
  assert.equal((await push(env, fetchImpl, { voidedPurchaseNotification: { orderId: "GPA.victim-1" } })).status, 200);
  assert.equal((await push(env, fetchImpl, voided({ purchaseToken: "tok-unknown", orderId: "GPA.victim-2" }))).status, 200);
  order.purchaseState = 1;
  assert.equal((await push(env, fetchImpl, voided({ orderId: "GPA.victim-3" }))).status, 200);
  assert.deepEqual(revokeKeys(env), []);
  for (const id of ["GPA.victim-1", "GPA.victim-2", "GPA.victim-3"]) assert.equal(env.CLAIMS.store.play_claims.has(id), false);
  assert.equal(env.CLAIMS.store.play_claims.get(order.orderId).revoked, 0);
  // Confirmed by Google (canceled, same order): revoked.
  assert.equal((await push(env, fetchImpl, voided())).status, 200);
  assert.deepEqual(revokeKeys(env), [`revoke:${lic.license_id}:void-${order.orderId}`]);
});

test("canceled_type2_active_purchase_not_revoked", async () => {
  const env = playEnv();
  const fetchImpl = googleWith({ "tok-1": purchased() });
  const lic = await claim(env, fetchImpl);
  assert.equal((await push(env, fetchImpl, canceled())).status, 200);
  assert.deepEqual(revokeKeys(env), []);
  assert.equal(env.CLAIMS.store.play_claims.get("GPA.3300-1111-2222-33333").revoked, 0);
  assert.equal((await claim(env, fetchImpl)).license_id, lic.license_id);
});
