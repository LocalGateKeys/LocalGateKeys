// POST /play/claim: a Google Play purchase token in, one LGK1- licence per Play
// order out. Google's OAuth and Play Developer API are a fake fetch.
import test from "node:test";
import assert from "node:assert/strict";

import { handle } from "../src/index.js";
import { SERVICE_ACCOUNT, fakeGoogle, purchased } from "./fake-google.mjs";
import { NOW, makeStoreEnv, postJson, verifyLicence } from "./store-helpers.mjs";

const playEnv = (extra = {}) => makeStoreEnv({ PLAY_SERVICE_ACCOUNT_JSON: SERVICE_ACCOUNT, ...extra });

function claim(env, fetchImpl, body = { purchaseToken: "tok-1", productId: "pro_unlimited" }, now = NOW) {
  return handle(postJson("/play/claim", body), env, { now, fetch: fetchImpl });
}

test("purchased_returns_lgk1", async () => {
  const env = playEnv();
  const google = fakeGoogle({ "tok-1": purchased() });
  const r = await claim(env, google);
  assert.equal(r.status, 200);
  const lic = verifyLicence((await r.json()).licence);
  assert.equal(lic.name, "Google Play purchase");
  assert.equal(lic.updates_until, "9999-12-31");
  assert.doesNotMatch(JSON.stringify(lic), /@/);
  assert.equal(env.CLAIMS.store.play_claims.get("GPA.3300-1111-2222-33333").licence_id, lic.license_id);
});

test("repeat_claim_same_licence", async () => {
  const env = playEnv();
  const google = fakeGoogle({ "tok-1": purchased(), "tok-2": purchased() });
  const first = await (await claim(env, google)).json();
  const again = await (await claim(env, google, { purchaseToken: "tok-2", productId: "pro_unlimited" }, NOW + 60000)).json();
  assert.equal(again.licence, first.licence);
  assert.equal(env.CLAIMS.store.play_claims.size, 1);
  // The access token is cached: one OAuth exchange for both claims.
  assert.equal(google.calls.filter((c) => c.url.includes("oauth2")).length, 1);
});

test("pending_state_400", async () => {
  const env = playEnv();
  const r = await claim(env, fakeGoogle({ "tok-1": purchased({ purchaseState: 2 }) }));
  assert.equal(r.status, 400);
  assert.equal(await r.text(), "Invalid\n");
  assert.equal(env.CLAIMS.store.play_claims.size, 0);
  // An unknown token (Google 404) looks the same.
  assert.equal((await claim(env, fakeGoogle({}))).status, 400);
});

test("consumed_400", async () => {
  const env = playEnv();
  assert.equal((await claim(env, fakeGoogle({ "tok-1": purchased({ consumptionState: 1 }) }))).status, 400);
});

test("test_purchase_400_unless_PLAY_ALLOW_TEST", async () => {
  const test = purchased({ purchaseType: 0, orderId: "GPA.test-1" });
  assert.equal((await claim(playEnv(), fakeGoogle({ "tok-1": test }))).status, 400);
  const allowed = await claim(playEnv({ PLAY_ALLOW_TEST: "1" }), fakeGoogle({ "tok-1": test }));
  assert.equal(allowed.status, 200);
  verifyLicence((await allowed.json()).licence);
  // Promo codes (purchaseType 1) are real purchases.
  assert.equal((await claim(playEnv(), fakeGoogle({ "tok-1": purchased({ purchaseType: 1 }) }))).status, 200);
});

test("google_5xx_returns_503", async () => {
  const env = playEnv();
  assert.equal((await claim(env, fakeGoogle({ "tok-1": 503 }))).status, 503);
  assert.equal((await claim(playEnv(), fakeGoogle({ "tok-1": purchased() }, { tokenStatus: 500 }))).status, 503);
  // No service account configured: unavailable, not invalid.
  assert.equal((await claim(makeStoreEnv(), fakeGoogle({ "tok-1": purchased() }))).status, 503);
  const throws = async () => {
    throw new TypeError("network down");
  };
  assert.equal((await claim(playEnv(), throws)).status, 503);
  assert.equal(env.CLAIMS.store.play_claims.size, 0);
});

test("wrong_product_400", async () => {
  const env = playEnv();
  const google = fakeGoogle({ "tok-1": purchased() });
  assert.equal((await claim(env, google, { purchaseToken: "tok-1", productId: "tip_jar" })).status, 400);
  assert.equal((await claim(env, google, { purchaseToken: "../../x", productId: "pro_unlimited" })).status, 400);
  assert.equal(google.calls.length, 0, "nothing asked of Google for a refused claim");
});
