// Google Play refunds: Real-time Developer Notifications pushed by Pub/Sub to
// POST /webhooks/play (Google OIDC token checked), and the daily Voided
// Purchases backstop (syncVoided, run by the cron trigger).
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import worker, { handle, runVoidedSync } from "../src/index.js";
import { VOIDED_CURSOR_KEY, VOIDED_RESUME_KEY, syncVoided } from "../src/play.js";
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
      if (page === "expired") return new Response("{}", { status: 400 });
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

test("unacknowledged_purchase_not_claimed", async () => {
  const env = playEnv();
  assert.equal(await claim(env, googleWith({ "tok-1": purchased({ acknowledgementState: 0 }) })), 400);
  assert.equal(typeof (await claim(env, googleWith({ "tok-1": purchased() }))), "object");
});

// Sales alerts: pushed only once a refund is confirmed and recorded, once per order or purchase token.
function recording(fetchImpl, sent) {
  return async (url, init) => {
    if (typeof url === "string" && url.startsWith("https://ntfy.sh/")) {
      sent.push(init.headers.Title);
      return new Response("ok");
    }
    return fetchImpl(url, init);
  };
}

test("play_refund_alert_only_after_confirmed_revoke_and_once", async () => {
  const env = { ...playEnv(), SALES_NTFY_TOPIC: "t" };
  const order = purchased();
  const google = googleWith({ "tok-1": order });
  const sent = [];
  const fetchImpl = recording(google, sent);
  await claim(env, google);
  const voided = { voidedPurchaseNotification: { purchaseToken: "tok-1", orderId: order.orderId, productType: 2, refundType: 1 } };
  // Not canceled yet, unknown token: no push.
  assert.equal((await push(env, fetchImpl, voided)).status, 200);
  assert.equal((await push(env, fetchImpl, { voidedPurchaseNotification: { purchaseToken: "tok-other" } })).status, 200);
  assert.deepEqual(sent, []);
  // D1 missing: 503 for redelivery, still no push.
  const noD1 = { ...env, CLAIMS: undefined };
  order.purchaseState = 1;
  assert.equal((await push(noD1, fetchImpl, voided)).status, 503);
  assert.deepEqual(sent, []);
  // Confirmed and recorded: one push, and none on redelivery.
  assert.equal((await push(env, fetchImpl, voided)).status, 200);
  assert.equal((await push(env, fetchImpl, voided)).status, 200);
  assert.equal((await push(env, fetchImpl, canceled())).status, 200);
  assert.deepEqual(sent, ["LocalGateKeys Pro refunded"]);
});

test("play_sold_alert_deduped_on_purchase_token", async () => {
  const env = { ...playEnv(), SALES_NTFY_TOPIC: "t" };
  const sent = [];
  const fetchImpl = recording(googleWith({ "tok-1": purchased() }), sent);
  const bought = (purchaseToken) => ({ oneTimeProductNotification: { notificationType: 1, purchaseToken, sku: "pro_unlimited" } });
  await push(env, fetchImpl, bought("tok-1"));
  await push(env, fetchImpl, bought("tok-1"));
  await push(env, fetchImpl, bought("tok-2"));
  assert.deepEqual(sent, ["LocalGateKeys Pro sold", "LocalGateKeys Pro sold"]);
});

// Scan F5: a backlog past one run's page budget is resumed, never skipped.
const voidedPage = (i, next) => ({
  voidedPurchases: [{ orderId: `GPA.page-${i}`, voidedTimeMillis: String(NOW - 100000 + i) }],
  ...(next === undefined ? {} : { tokenPagination: { nextPageToken: String(next) } }),
});

test("voided_cron_resumes_a_backlog_past_the_page_budget (scan F5)", async () => {
  const env = { ...playEnv(), SALES_NTFY_TOPIC: "t" };
  const pages = [0, 1, 2, 3, 4].map((i) => voidedPage(i, i < 4 ? i + 1 : undefined));
  const sent = [];
  const google = googleWith({}, pages);
  const fetchImpl = recording(google, sent);
  const deps = { now: NOW, fetch: fetchImpl, voided: { maxPages: 2 } };
  // Run 1 reads pages 0-1, keeps the cursor, saves page 2 and alerts once.
  assert.equal(await runVoidedSync(env, deps), 2);
  assert.equal(env.LICENSES.data.get(VOIDED_CURSOR_KEY), undefined);
  const resume = JSON.parse(env.LICENSES.data.get(VOIDED_RESUME_KEY));
  assert.equal(resume.token, "2");
  assert.deepEqual(sent, ["LocalGateKeys Play refund check incomplete"]);
  // Run 2 continues at page 2 with the same start time; the same backlog does not alert again.
  assert.equal(await runVoidedSync(env, { ...deps, now: NOW + 86400000 }), 2);
  const queries = google.voidedQueries;
  assert.equal(queries[2].token, "2");
  assert.equal(queries[2].startTime, queries[0].startTime);
  assert.equal(sent.length, 1);
  // Run 3 finishes: every page handled, the cursor moves to the newest entry, the resume is gone.
  assert.equal(await runVoidedSync(env, { ...deps, now: NOW + 2 * 86400000 }), 1);
  for (let i = 0; i < 5; i++) assert.equal(env.CLAIMS.store.play_claims.get(`GPA.page-${i}`).revoked, 1, `page ${i}`);
  assert.equal(env.LICENSES.data.get(VOIDED_CURSOR_KEY), String(NOW - 100000 + 4));
  assert.equal(env.LICENSES.data.has(VOIDED_RESUME_KEY), false);
});

test("voided_cron_stops_on_its_time_budget and restarts a refused page token (scan F5)", async () => {
  const env = playEnv();
  const pages = [voidedPage(0, 1), voidedPage(1, 2), voidedPage(2)];
  const fetchImpl = googleWith({}, pages);
  let t = 0;
  const clock = () => (t += 1000);
  // Budget of 2.5 s on a clock that moves 1 s per check: two pages, then it stops.
  assert.equal(await syncVoided(env, fetchImpl, NOW, { clock, budgetMs: 2500 }), 2);
  assert.equal(JSON.parse(env.LICENSES.data.get(VOIDED_RESUME_KEY)).token, "2");
  // Google no longer accepts the saved token: the query starts again from its first page.
  pages[2] = "expired";
  pages[0] = voidedPage(0, 1);
  pages[1] = voidedPage(1);
  assert.equal(await syncVoided(env, fetchImpl, NOW + 1000), 2);
  assert.equal(env.LICENSES.data.has(VOIDED_RESUME_KEY), false);
  assert.equal(env.LICENSES.data.get(VOIDED_CURSOR_KEY), String(NOW - 100000 + 1));
});
