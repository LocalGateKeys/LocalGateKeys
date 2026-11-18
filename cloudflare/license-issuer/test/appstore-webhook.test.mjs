// POST /webhooks/appstore: App Store Server Notifications V2. REFUND and REVOKE
// write the same `revoke:` records as Paddle refunds.
import test from "node:test";
import assert from "node:assert/strict";

import { handle } from "../src/index.js";
import { revocationIds } from "../scripts/revocation-list.mjs";
import { makeTestCa, transactionPayload } from "./apple-test-ca.mjs";
import { NOW, makeStoreEnv, postJson, revokeKeys, verifyLicence } from "./store-helpers.mjs";

const ca = await makeTestCa();
const deps = { now: NOW, appleRootSha256: ca.rootSha256 };

async function claim(env) {
  return handle(postJson("/appstore/claim", { jws: await ca.sign(transactionPayload()) }), env, deps);
}

async function notify(env, notificationType, { signer = ca, tx = transactionPayload({ revocationDate: NOW }), signedDate = NOW } = {}) {
  const signedPayload = await signer.sign({
    notificationType,
    notificationUUID: `uuid-${notificationType}`,
    signedDate,
    data: { bundleId: "app.localgatekeys.app", environment: "Production", signedTransactionInfo: await signer.sign(tx) },
  });
  return handle(postJson("/webhooks/appstore", { signedPayload }), env, deps);
}

test("refund_after_claim_writes_revoke", async () => {
  const env = makeStoreEnv();
  const lic = verifyLicence((await (await claim(env)).json()).licence);
  const r = await notify(env, "REFUND");
  assert.equal(r.status, 200);
  assert.deepEqual(revokeKeys(env), [`revoke:${lic.license_id}:uuid-REFUND`]);
  const record = env.LICENSES.meta.get(`revoke:${lic.license_id}:uuid-REFUND`);
  assert.equal(record.provider, "appstore");
  assert.equal(record.revoke, true);
  // The weekly list script picks it up.
  const entries = [...env.LICENSES.meta].map(([name, metadata]) => ({ name, metadata }));
  assert.deepEqual(revocationIds(entries).ids, [lic.license_id]);
  // And the purchase cannot be claimed again.
  assert.equal((await claim(env)).status, 403);
});

test("refund_reversed_reinstates", async () => {
  const env = makeStoreEnv();
  const lic = verifyLicence((await (await claim(env)).json()).licence);
  assert.equal((await notify(env, "REFUND", { tx: transactionPayload({ revocationDate: NOW - 60_000 }) })).status, 200);
  assert.equal((await claim(env)).status, 403);
  assert.equal((await notify(env, "REFUND_REVERSED", { tx: transactionPayload() })).status, 200);
  assert.equal(env.CLAIMS.store.appstore_claims.get("2000000111111111").revoked, 0);
  const record = env.LICENSES.meta.get(`revoke:${lic.license_id}:uuid-REFUND_REVERSED`);
  assert.equal(record.reinstate, true);
  assert.equal(record.revoke, false);
  const entries = [...env.LICENSES.meta].map(([name, metadata]) => ({ name, metadata }));
  const result = revocationIds(entries, [lic.license_id]);
  assert.deepEqual(result.reinstated, [lic.license_id]);
  assert.deepEqual(revocationIds(entries).ids, []);
  // The purchase can be claimed again, with the same licence.
  assert.equal(verifyLicence((await (await claim(env)).json()).licence).license_id, lic.license_id);
  // A forged notice changes nothing.
  const stranger = await makeTestCa();
  assert.equal((await notify(env, "REFUND_REVERSED", { signer: stranger })).status, 400);
});

test("revoke_type_writes_revoke", async () => {
  const env = makeStoreEnv();
  const lic = verifyLicence((await (await claim(env)).json()).licence);
  assert.equal((await notify(env, "REVOKE")).status, 200);
  assert.deepEqual(revokeKeys(env), [`revoke:${lic.license_id}:uuid-REVOKE`]);
});

test("refund_before_claim_blocks", async () => {
  const env = makeStoreEnv();
  assert.equal((await notify(env, "REFUND")).status, 200);
  assert.deepEqual(revokeKeys(env), [], "nothing issued, nothing to list");
  const row = env.CLAIMS.store.appstore_claims.get("2000000111111111");
  assert.equal(row.revoked, 1);
  assert.equal(row.licence_id, null);
  assert.equal((await claim(env)).status, 403);
});

test("refund_before_claim_then_reversed_can_claim", async () => {
  const env = makeStoreEnv();
  assert.equal((await notify(env, "REFUND", { tx: transactionPayload({ revocationDate: NOW - 60_000 }) })).status, 200);
  assert.equal((await claim(env)).status, 403);
  assert.equal((await notify(env, "REFUND_REVERSED", { tx: transactionPayload() })).status, 200);
  const first = await claim(env);
  assert.equal(first.status, 200);
  const lic = verifyLicence((await first.json()).licence);
  // Repeat claims read back the same licence.
  assert.equal(verifyLicence((await (await claim(env)).json()).licence).license_id, lic.license_id);
  assert.equal(env.CLAIMS.store.appstore_claims.get("2000000111111111").licence_id, lic.license_id);
});

test("retried_refund_after_reversal_is_ignored", async () => {
  const env = makeStoreEnv();
  const lic = verifyLicence((await (await claim(env)).json()).licence);
  const refundTx = transactionPayload({ revocationDate: NOW - 60_000 });
  assert.equal((await notify(env, "REFUND", { tx: refundTx })).status, 200);
  assert.equal((await notify(env, "REFUND_REVERSED", { tx: transactionPayload() })).status, 200);
  // Apple retries the older REFUND: the purchase stays reinstated.
  env.LICENSES.meta.delete(`revoke:${lic.license_id}:uuid-REFUND`);
  assert.equal((await notify(env, "REFUND", { tx: refundTx })).status, 200);
  assert.equal(env.CLAIMS.store.appstore_claims.get("2000000111111111").revoked, 0);
  assert.equal(env.LICENSES.meta.has(`revoke:${lic.license_id}:uuid-REFUND`), false);
  assert.equal((await claim(env)).status, 200);
  // A stale reversal (signed before a newer refund) does not reinstate either.
  assert.equal((await notify(env, "REFUND", { tx: transactionPayload({ revocationDate: NOW + 60_000 }) })).status, 200);
  assert.equal((await notify(env, "REFUND_REVERSED", { tx: transactionPayload() })).status, 200);
  assert.equal(env.CLAIMS.store.appstore_claims.get("2000000111111111").revoked, 1);
  assert.equal((await claim(env)).status, 403);
});

test("other_type_ignored_200", async () => {
  const env = makeStoreEnv();
  await claim(env);
  for (const type of ["CONSUMPTION_REQUEST", "REFUND_DECLINED", "TEST"]) {
    assert.equal((await notify(env, type, { tx: transactionPayload() })).status, 200);
  }
  assert.deepEqual(revokeKeys(env), []);
  assert.equal(env.CLAIMS.store.appstore_claims.get("2000000111111111").revoked, 0);
});

test("bad_signature_400", async () => {
  const env = makeStoreEnv();
  await claim(env);
  const stranger = await makeTestCa();
  const r = await notify(env, "REFUND", { signer: stranger });
  assert.equal(r.status, 400);
  assert.equal(await r.text(), "Invalid\n");
  assert.equal((await handle(postJson("/webhooks/appstore", "{}"), env, deps)).status, 400);
  assert.deepEqual(revokeKeys(env), []);
  assert.equal((await claim(env)).status, 200);
});

// Sales alerts (src/sales-alert.js): a push through ntfy when SALES_NTFY_TOPIC is set.
async function notifyWithAlerts(env, notificationType, tx) {
  const sent = [];
  const fetch = async (url, init) => {
    sent.push({ url, title: init.headers.Title, body: init.body });
    return new Response("ok");
  };
  const signedPayload = await ca.sign({
    notificationType,
    notificationUUID: `uuid-${notificationType}`,
    signedDate: NOW,
    data: { bundleId: "app.localgatekeys.app", environment: "Production", signedTransactionInfo: await ca.sign(tx) },
  });
  const r = await handle(postJson("/webhooks/appstore", { signedPayload }), env, { ...deps, fetch });
  return { r, sent };
}

test("one_time_charge_sends_sales_alert", async () => {
  const env = { ...makeStoreEnv(), SALES_NTFY_TOPIC: "lgk-sales-test" };
  const tx = transactionPayload({ price: 12990, currency: "USD", storefront: "USA" });
  const { r, sent } = await notifyWithAlerts(env, "ONE_TIME_CHARGE", tx);
  assert.equal(r.status, 200);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].url, "https://ntfy.sh/lgk-sales-test");
  assert.equal(sent[0].title, "LocalGateKeys Pro sold");
  assert.match(sent[0].body, /12\.99 USD \(USA\)/);
  assert.deepEqual(revokeKeys(env), []);
});

test("refund_sends_alert_and_still_revokes", async () => {
  const env = { ...makeStoreEnv(), SALES_NTFY_TOPIC: "t" };
  const { r, sent } = await notifyWithAlerts(env, "REFUND", transactionPayload({ revocationDate: NOW }));
  assert.equal(r.status, 200);
  assert.equal(sent[0].title, "LocalGateKeys Pro refunded");
  assert.equal(env.CLAIMS.store.appstore_claims.get("2000000111111111").revoked, 1);
});

test("no_topic_no_alert_and_failed_alert_is_harmless", async () => {
  const quiet = await notifyWithAlerts(makeStoreEnv(), "ONE_TIME_CHARGE", transactionPayload());
  assert.equal(quiet.sent.length, 0);
  const env = { ...makeStoreEnv(), SALES_NTFY_TOPIC: "t" };
  const signedPayload = await ca.sign({ notificationType: "ONE_TIME_CHARGE", signedDate: NOW,
    data: { signedTransactionInfo: await ca.sign(transactionPayload()) } });
  const r = await handle(postJson("/webhooks/appstore", { signedPayload }), env,
    { ...deps, fetch: async () => { throw new Error("down"); } });
  assert.equal(r.status, 200);
});

test("appstore_alert_after_environment_check_and_record_once", async () => {
  // Sandbox notices are not alerted unless sandbox is allowed.
  const sandbox = { ...makeStoreEnv(), SALES_NTFY_TOPIC: "t" };
  const sb = await notifyWithAlerts(sandbox, "ONE_TIME_CHARGE", transactionPayload({ environment: "Sandbox" }));
  assert.equal(sb.r.status, 200);
  assert.equal(sb.sent.length, 0);
  // D1 missing: 503 so Apple retries, and no push before it.
  const noD1 = { ...makeStoreEnv(), SALES_NTFY_TOPIC: "t", CLAIMS: undefined };
  const down = await notifyWithAlerts(noD1, "REFUND", transactionPayload({ revocationDate: NOW }));
  assert.equal(down.r.status, 503);
  assert.equal(down.sent.length, 0);
  // The same notification UUID redelivered pushes once.
  const env = { ...makeStoreEnv(), SALES_NTFY_TOPIC: "t" };
  const first = await notifyWithAlerts(env, "REFUND", transactionPayload({ revocationDate: NOW }));
  const again = await notifyWithAlerts(env, "REFUND", transactionPayload({ revocationDate: NOW }));
  assert.equal(first.sent.length + again.sent.length, 1);
  const sold1 = await notifyWithAlerts(env, "ONE_TIME_CHARGE", transactionPayload());
  const sold2 = await notifyWithAlerts(env, "ONE_TIME_CHARGE", transactionPayload());
  assert.equal(sold1.sent.length + sold2.sent.length, 1);
});

test("failed_sales_alert_is_retried_and_not_marked_sent", async () => {
  const env = { ...makeStoreEnv(), SALES_NTFY_TOPIC: "t" };
  const tx = transactionPayload();
  const signedPayload = await ca.sign({ notificationType: "ONE_TIME_CHARGE", notificationUUID: "uuid-retry", signedDate: NOW,
    data: { bundleId: "app.localgatekeys.app", environment: "Production", signedTransactionInfo: await ca.sign(tx) } });
  // ntfy refuses both tries (rate limit): nothing marked, so a redelivery pushes again.
  let calls = 0;
  await handle(postJson("/webhooks/appstore", { signedPayload }), env,
    { ...deps, fetch: async () => { calls++; return new Response("slow down", { status: 429 }); } });
  assert.equal(calls, 2);
  // First try fails, the in-call retry succeeds.
  const sent = [];
  let n = 0;
  await handle(postJson("/webhooks/appstore", { signedPayload }), env,
    { ...deps, fetch: async (url) => { n++; if (n === 1) throw new Error("timeout"); sent.push(url); return new Response("ok"); } });
  assert.equal(sent.length, 1);
  // Now marked: a third delivery stays quiet.
  const again = [];
  await handle(postJson("/webhooks/appstore", { signedPayload }), env,
    { ...deps, fetch: async (url) => { again.push(url); return new Response("ok"); } });
  assert.equal(again.length, 0);
});

test("test_alert_needs_token", async () => {
  const token = "x".repeat(40);
  const env = { ...makeStoreEnv(), SALES_NTFY_TOPIC: "t", ALERT_TEST_TOKEN: token };
  const sent = [];
  const d = { ...deps, fetch: async (u) => { sent.push(u); return new Response("ok"); } };
  const req = (auth) => new Request("https://x/admin/test-alert", { method: "POST", headers: auth ? { Authorization: auth } : {} });
  assert.equal((await handle(req(), env, d)).status, 404);
  assert.equal((await handle(req("Bearer wrong"), env, d)).status, 404);
  assert.equal((await handle(req(`Bearer ${token}`), { ...env, ALERT_TEST_TOKEN: undefined }, d)).status, 404);
  assert.equal(sent.length, 0);
  assert.equal((await handle(req(`Bearer ${token}`), env, d)).status, 200);
  assert.equal(sent.length, 1);
});

test("sales_alert_also_emails_and_email_alone_marks_sent", async () => {
  const mails = [];
  const env = { ...makeStoreEnv(), SALES_NTFY_TOPIC: "t", SALES_EMAIL_TO: "owner@example.com",
    SALES_EMAIL: { send: async (m) => { mails.push(m); } } };
  const makeEmail = async (from, to, raw) => ({ from, to, raw });
  const signedPayload = await ca.sign({ notificationType: "ONE_TIME_CHARGE", notificationUUID: "uuid-mail", signedDate: NOW,
    data: { bundleId: "app.localgatekeys.app", environment: "Production", signedTransactionInfo: await ca.sign(transactionPayload()) } });
  const down = async () => { throw new Error("timeout"); };
  await handle(postJson("/webhooks/appstore", { signedPayload }), env, { ...deps, fetch: down, makeEmail });
  assert.equal(mails.length, 1);
  assert.equal(mails[0].to, "owner@example.com");
  assert.match(mails[0].raw, /Subject: LocalGateKeys Pro sold\r\n/);
  // ntfy failed but the email went: marked, so a redelivery stays quiet.
  await handle(postJson("/webhooks/appstore", { signedPayload }), env, { ...deps, fetch: down, makeEmail });
  assert.equal(mails.length, 1);
});
