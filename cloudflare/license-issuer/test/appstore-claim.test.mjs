// POST /appstore/claim: an App Store transaction JWS in, one LGK1- licence per
// original purchase out. The Apple chain is the generated test CA.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { handle } from "../src/index.js";
import { makeTestCa, transactionPayload } from "./apple-test-ca.mjs";
import { NOW, makeStoreEnv, postJson, verifyLicence } from "./store-helpers.mjs";

const ca = await makeTestCa();
const deps = { now: NOW, appleRootSha256: ca.rootSha256 };

async function claim(env, payload, headers) {
  const jws = typeof payload === "string" ? payload : await ca.sign(payload);
  return handle(postJson("/appstore/claim", { jws }, headers), env, deps);
}

test("claim_returns_lgk1", async () => {
  const env = makeStoreEnv();
  const r = await claim(env, transactionPayload());
  assert.equal(r.status, 200);
  assert.match(r.headers.get("Content-Type"), /application\/json/);
  const { licence } = await r.json();
  const lic = verifyLicence(licence);
  assert.equal(lic.name, "App Store purchase");
  assert.equal(lic.updates_until, "9999-12-31");
  assert.equal(lic.edition, "pro");
  assert.doesNotMatch(JSON.stringify(lic), /@/, "no email address in a store licence");
  assert.match(lic.license_id, /^lgk_[0-9A-HJKMNP-TV-Z]{26}$/);
});

test("repeat_claim_same_licence", async () => {
  const env = makeStoreEnv();
  const first = await (await claim(env, transactionPayload())).json();
  // Restore on another device: a new transaction id, same original purchase, a later day.
  const again = await (
    await handle(
      postJson("/appstore/claim", { jws: await ca.sign(transactionPayload({ transactionId: "2000000999999999" })) }),
      env,
      { ...deps, now: NOW + 86400000 },
    )
  ).json();
  assert.equal(again.licence, first.licence);
  assert.equal(env.CLAIMS.store.appstore_claims.size, 1);
});

test("wrong_bundle_400", async () => {
  const env = makeStoreEnv();
  const r = await claim(env, transactionPayload({ bundleId: "com.example.other" }));
  assert.equal(r.status, 400);
  assert.equal(await r.text(), "Invalid\n");
  assert.equal(env.CLAIMS.store.appstore_claims.size, 0);
  // A bad signature or garbage gives the same answer.
  assert.equal(await (await claim(env, "a.b.c")).text(), "Invalid\n");
  const garbage = await handle(postJson("/appstore/claim", "{not json"), env, deps);
  assert.equal(garbage.status, 400);
});

test("wrong_product_400", async () => {
  const env = makeStoreEnv();
  assert.equal((await claim(env, transactionPayload({ productId: "tip_jar" }))).status, 400);
});

test("revocationDate_403", async () => {
  const env = makeStoreEnv();
  const r = await claim(env, transactionPayload({ revocationDate: NOW - 1000, revocationReason: 0 }));
  assert.equal(r.status, 403);
  assert.equal(env.CLAIMS.store.appstore_claims.size, 0);
});

test("sandbox_400_unless_APPSTORE_ALLOW_SANDBOX", async () => {
  const sandbox = transactionPayload({ environment: "Sandbox" });
  assert.equal((await claim(makeStoreEnv(), sandbox)).status, 400);
  assert.equal((await claim(makeStoreEnv({ APPSTORE_ALLOW_SANDBOX: "" }), sandbox)).status, 400);
  assert.equal((await claim(makeStoreEnv(), transactionPayload({ environment: "Xcode" }))).status, 400);
  const allowed = await claim(makeStoreEnv({ APPSTORE_ALLOW_SANDBOX: "1" }), sandbox);
  assert.equal(allowed.status, 200);
  verifyLicence((await allowed.json()).licence);
});

// --- App Store Server API re-check (Get Transaction Info) -----------------------

// TEST ONLY: a throwaway ES256 key standing in for the App Store Connect .p8.
const apiKey = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const API_SECRETS = {
  APPSTORE_API_ISSUER_ID: "57246542-96fe-1a63-e053-0824d011072a",
  APPSTORE_API_KEY_ID: "TESTKEY123",
  APPSTORE_API_PRIVATE_KEY: apiKey.privateKey.export({ type: "pkcs8", format: "pem" }),
};

// Apple's API: `answer` is a transaction payload (signed by the test CA), or an HTTP status.
function fakeApple(answer) {
  const calls = [];
  async function fetchImpl(url, init = {}) {
    url = String(url);
    calls.push(url);
    const [h, p, s] = new Headers(init.headers).get("Authorization").replace(/^Bearer /, "").split(".");
    const header = JSON.parse(Buffer.from(h, "base64url"));
    const claims = JSON.parse(Buffer.from(p, "base64url"));
    assert.deepEqual(header, { alg: "ES256", kid: "TESTKEY123", typ: "JWT" });
    assert.equal(claims.iss, API_SECRETS.APPSTORE_API_ISSUER_ID);
    assert.equal(claims.aud, "appstoreconnect-v1");
    assert.equal(claims.bid, "app.localgatekeys.app");
    assert.ok(claims.exp - claims.iat <= 3600 && claims.exp > claims.iat);
    assert.ok(
      crypto.verify("sha256", Buffer.from(`${h}.${p}`), { key: apiKey.publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url")),
      "ES256 bearer token",
    );
    if (typeof answer === "number") return new Response("{}", { status: answer });
    if (answer instanceof Error) throw answer;
    return Response.json({ signedTransactionInfo: await ca.sign(answer) });
  }
  fetchImpl.calls = calls;
  return fetchImpl;
}

const apiClaim = (env, fetchImpl, payload = transactionPayload()) =>
  ca.sign(payload).then((jws) => handle(postJson("/appstore/claim", { jws }), env, { ...deps, fetch: fetchImpl }));

test("server_api_refunded_answer_403", async () => {
  const env = makeStoreEnv(API_SECRETS);
  const fetchImpl = fakeApple(transactionPayload({ revocationDate: NOW - 5000, revocationReason: 0, signedDate: NOW - 1000 }));
  // The client's JWS predates the refund (no revocationDate) but Apple knows better.
  const r = await apiClaim(env, fetchImpl);
  assert.equal(r.status, 403);
  assert.deepEqual(fetchImpl.calls, ["https://api.storekit.itunes.apple.com/inApps/v1/transactions/2000000111111111"]);
  const row = env.CLAIMS.store.appstore_claims.get("2000000111111111");
  assert.equal(row.revoked, 1);
  assert.equal(row.licence_id, null);
  // Sandbox purchases go to the sandbox host.
  const sandboxEnv = makeStoreEnv({ ...API_SECRETS, APPSTORE_ALLOW_SANDBOX: "1" });
  const sandboxFetch = fakeApple(transactionPayload({ environment: "Sandbox" }));
  assert.equal((await apiClaim(sandboxEnv, sandboxFetch, transactionPayload({ environment: "Sandbox" }))).status, 200);
  assert.match(sandboxFetch.calls[0], /^https:\/\/api\.storekit-sandbox\.itunes\.apple\.com\/inApps\/v1\/transactions\//);
});

test("server_api_active_answer_issues", async () => {
  const env = makeStoreEnv(API_SECRETS);
  const r = await apiClaim(env, fakeApple(transactionPayload()));
  assert.equal(r.status, 200);
  verifyLicence((await r.json()).licence);
  // Apple's answer for another purchase is refused.
  const other = await apiClaim(makeStoreEnv(API_SECRETS), fakeApple(transactionPayload({ originalTransactionId: "2000000222222222" })));
  assert.equal(other.status, 400);
});

test("server_api_failure_503", async () => {
  for (const answer of [500, 503, 429, 401, new TypeError("network down")]) {
    const env = makeStoreEnv(API_SECRETS);
    const r = await apiClaim(env, fakeApple(answer));
    assert.equal(r.status, 503, String(answer));
    assert.equal(env.CLAIMS.store.appstore_claims.size, 0);
  }
  // An answer that does not verify is also 503 (retry), never a licence.
  const env = makeStoreEnv(API_SECRETS);
  const bad = async () => Response.json({ signedTransactionInfo: "a.b.c" });
  const fetchImpl = async (url, init) => (fakeApple(transactionPayload())(url, init), bad());
  assert.equal((await apiClaim(env, fetchImpl)).status, 503);
  // Apple does not know the transaction: 400.
  assert.equal((await apiClaim(makeStoreEnv(API_SECRETS), fakeApple(404))).status, 400);
});

test("no_server_api_credentials_unchanged", async () => {
  const env = makeStoreEnv({ APPSTORE_API_ISSUER_ID: "57246542-96fe-1a63-e053-0824d011072a" }); // incomplete
  const fetchImpl = async () => assert.fail("no Apple call without credentials");
  const warnings = [];
  const realWarn = console.warn;
  console.warn = (msg) => warnings.push(String(msg));
  try {
    const r = await apiClaim(env, fetchImpl);
    assert.equal(r.status, 200);
    verifyLicence((await r.json()).licence);
  } finally {
    console.warn = realWarn;
  }
  assert.ok(warnings.length <= 1);
  for (const w of warnings) assert.doesNotMatch(w, /BEGIN|57246542/);
});

test("rate_limited_429", async () => {
  const env = makeStoreEnv();
  const statuses = [];
  for (let i = 0; i < 21; i++) statuses.push((await claim(env, "x.y.z")).status);
  assert.deepEqual(statuses.slice(0, 20), Array(20).fill(400));
  const limited = await claim(env, transactionPayload());
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers.get("Retry-After")) > 0);
  // Another IP is not limited; the KV key holds no IP address.
  assert.equal((await claim(env, transactionPayload(), { "CF-Connecting-IP": "198.51.100.1" })).status, 200);
  const keys = [...env.LICENSES.data.keys()].filter((k) => k.startsWith("store-claim-throttle:"));
  assert.equal(keys.length, 2);
  for (const key of keys) assert.doesNotMatch(key, /203\.0\.113|198\.51/);
});
