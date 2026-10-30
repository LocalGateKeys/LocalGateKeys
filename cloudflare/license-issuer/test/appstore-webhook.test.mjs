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

async function notify(env, notificationType, { signer = ca, tx = transactionPayload({ revocationDate: NOW }) } = {}) {
  const signedPayload = await signer.sign({
    notificationType,
    notificationUUID: `uuid-${notificationType}`,
    signedDate: NOW,
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
