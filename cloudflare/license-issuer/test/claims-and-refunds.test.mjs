// Security fixes 2026-10-24 (docs/SECURITY_AUDIT_EXTENDED_2026-10-24.md):
// M-2 (claims only from web checkouts), L-1 (claim bound to its first order,
// recovery by order id + email), L-2 (idempotent issuance), L-3 (refund and
// chargeback records for revocation), plus the D1 claim arbitration (L-2) and
// the /recover throttle (R-6). KV, D1 and Paddle are in-memory fakes.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { handle } from "../src/index.js";
import { parsePaddle } from "../src/providers.js";
import { LICENSE_KEY_ID, fallbackTokenForOrder, issueBundle, licenseIdForOrder } from "../src/sign.js";
import { revocationIds } from "../scripts/revocation-list.mjs";
import { fakeD1 } from "./fake-d1.mjs";

// TEST ONLY: the throwaway key from tests/license-issuer.test.cjs. It signs nothing real.
const PK = "MC4CAQAwBQYDK2VwBCIEIAbQx1FfuhaeywNI9WhH4kiEiWHlqopq/NpubKWX0HYk";
const SECRET = "whsec-test";
const NOW = Date.parse("2026-10-24T12:00:00Z");
const CLAIM = "V".repeat(43);
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

const CUSTOMERS = {
  ctm_victim: { email: "victim@example.com", name: "Victim V" },
  ctm_other: { email: "Other@Example.com", name: "Other O" },
};

// `mode`: "consistent" (reads see every earlier write), or "stale" (a read
// returns what was there when it started, then waits: KV-like lag).
function fakeKv(mode = "consistent") {
  const data = new Map();
  const meta = new Map();
  const puts = [];
  const gets = [];
  return {
    data,
    meta,
    puts,
    gets,
    async get(key) {
      gets.push(key);
      const value = data.has(key) ? data.get(key) : null;
      if (mode === "stale") await new Promise((r) => setTimeout(r, 10));
      return value;
    },
    async put(key, value, options) {
      puts.push(key);
      data.set(key, value);
      if (options?.metadata) meta.set(key, options.metadata);
    },
  };
}

function makeEnv(kvMode, extra = {}) {
  return {
    LICENSES: fakeKv(kvMode),
    CLAIMS: fakeD1(),
    LICENSE_PRIVATE_KEY: PK,
    LICENSE_KEY_ID_OVERRIDE: "1fb2572acef33ca2", // the test key; production pins 9f76e21ed03c0482
    WEBHOOK_SECRET: SECRET,
    PADDLE_API_KEY: "pdl_test",
    PRODUCT_IDS: "pro_1",
    PROVIDER: "paddle",
    ...extra,
  };
}

const fakeFetch = async (url) => {
  const id = decodeURIComponent(url.split("/").pop());
  return new Response(JSON.stringify({ data: CUSTOMERS[id] }), { status: 200 });
};
let deps = { now: NOW, fetch: fakeFetch };

function transaction(id, customer, claim, origin = "web") {
  const data = { id, customer_id: customer, custom_data: { lgk_claim: claim }, items: [{ price: { product_id: "pro_1" } }] };
  if (origin !== undefined) data.origin = origin;
  return JSON.stringify({ event_type: "transaction.completed", data });
}

function adjustmentEvent(id, txn, { action = "refund", status = "approved", type = "full", eventType = "adjustment.created", occurredAt = "2026-10-24T13:00:00Z" } = {}) {
  return JSON.stringify({
    event_type: eventType,
    occurred_at: occurredAt,
    data: { id, transaction_id: txn, action, status, type, customer_id: "ctm_victim" },
  });
}

async function webhook(env, body, { provider = "paddle", sign = true } = {}) {
  const ts = Math.floor(NOW / 1000);
  const headers = {};
  if (provider === "paddle") {
    const h1 = crypto.createHmac("sha256", SECRET).update(`${ts}:${body}`).digest("hex");
    headers["Paddle-Signature"] = `ts=${ts};h1=${sign ? h1 : "00".repeat(32)}`;
  } else {
    headers["X-Signature"] = crypto.createHmac("sha256", SECRET).update(body).digest("hex");
  }
  const request = new Request(`https://licenses.example/webhooks/${provider}`, { method: "POST", body, headers });
  return handle(request, env, deps);
}

const tokenOf = (env, orderKey) => env.LICENSES.data.get(orderKey);
const bundleAt = (env, token) => JSON.parse(env.LICENSES.data.get(`license:${token}`));

async function pageHolder(env, token) {
  const html = await (await handle(new Request(`https://licenses.example/license/${token}`), env, deps)).text();
  return (html.match(/Licensed to ([^<]*)\./) ?? [null, "PENDING"])[1];
}

function recoverRequest(env, fields) {
  const body = new URLSearchParams(fields).toString();
  const request = new Request("https://licenses.example/recover", {
    method: "POST",
    body,
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  return handle(request, env, deps);
}

// --- M-2 ---------------------------------------------------------------------

test("M-2: a claim on a transaction not opened by the web checkout is ignored", async () => {
  for (const origin of ["api", "subscription_recurring", "subscription_charge", ""]) {
    const env = makeEnv();
    assert.equal((await webhook(env, transaction("txn_api", "ctm_victim", CLAIM, origin))).status, 200);
    const token = tokenOf(env, "order:paddle:txn_api");
    assert.match(token, TOKEN);
    assert.notEqual(token, CLAIM, origin);
    assert.equal(env.CLAIMS.rows.size, 0);
    assert.equal(await pageHolder(env, CLAIM), "PENDING");
    assert.equal(bundleAt(env, token).license.email, "victim@example.com");
  }
});

test("M-2: a web checkout's claim is honoured", async () => {
  const env = makeEnv();
  await webhook(env, transaction("txn_web", "ctm_victim", CLAIM, "web"));
  assert.equal(tokenOf(env, "order:paddle:txn_web"), CLAIM);
  const row = env.CLAIMS.rows.get(CLAIM);
  assert.equal(row.order_key, "order:paddle:txn_web");
  assert.equal(row.licence_id, await licenseIdForOrder("order:paddle:txn_web"));
  assert.equal(row.created_at, NOW / 1000);
  assert.equal(env.LICENSES.data.has(`claim:${CLAIM}`), false, "KV no longer arbitrates");
  assert.equal(await pageHolder(env, CLAIM), "Victim V (victim@example.com)");
  assert.equal(parsePaddle(JSON.parse(transaction("t", "c", CLAIM, "api")), { PRODUCT_IDS: "pro_1" }).claim, null);
  assert.equal(parsePaddle(JSON.parse(transaction("t", "c", CLAIM, "web")), { PRODUCT_IDS: "pro_1" }).claim, CLAIM);
});

// --- L-1 ---------------------------------------------------------------------

test("L-1: a second order with a used claim gets its own token; the first page keeps its licence", async () => {
  const env = makeEnv();
  await webhook(env, transaction("txn_first", "ctm_victim", CLAIM));
  await webhook(env, transaction("txn_second", "ctm_other", CLAIM));
  assert.equal(tokenOf(env, "order:paddle:txn_first"), CLAIM);
  const second = tokenOf(env, "order:paddle:txn_second");
  assert.match(second, TOKEN);
  assert.notEqual(second, CLAIM);
  assert.equal(second, await fallbackTokenForOrder("order:paddle:txn_second", PK));
  assert.equal(await pageHolder(env, CLAIM), "Victim V (victim@example.com)");
  assert.equal(await pageHolder(env, second), "Other O (Other@Example.com)");
  assert.equal(env.CLAIMS.rows.get(CLAIM).order_key, "order:paddle:txn_first");
});

test("L-1: a claim bound in KV by an older deploy stays with its order", async () => {
  const env = makeEnv();
  env.LICENSES.data.set(`claim:${CLAIM}`, "order:paddle:txn_old");
  await webhook(env, transaction("txn_new", "ctm_victim", CLAIM));
  assert.notEqual(tokenOf(env, "order:paddle:txn_new"), CLAIM);
  assert.equal(env.CLAIMS.rows.size, 0);
  assert.equal(await pageHolder(env, CLAIM), "PENDING");
});

test("L-1: a claim whose licence predates claim binding counts as used", async () => {
  const env = makeEnv();
  env.LICENSES.data.set(`license:${CLAIM}`, JSON.stringify({ license: { email: "old@example.com", name: "Old" } }));
  await webhook(env, transaction("txn_new", "ctm_victim", CLAIM));
  assert.notEqual(tokenOf(env, "order:paddle:txn_new"), CLAIM);
  assert.equal(JSON.parse(env.LICENSES.data.get(`license:${CLAIM}`)).license.email, "old@example.com");
});

test("L-1: recovery by order id and email redirects to that order's licence page", async () => {
  const env = makeEnv();
  await webhook(env, transaction("txn_first", "ctm_victim", CLAIM));
  await webhook(env, transaction("txn_second", "ctm_other", CLAIM));
  const second = tokenOf(env, "order:paddle:txn_second");

  const ok = await recoverRequest(env, { order: " txn_second ", email: "other@EXAMPLE.com" });
  assert.equal(ok.status, 303);
  assert.equal(ok.headers.get("Location"), `/license/${second}`);
  const first = await recoverRequest(env, { order: "txn_first", email: "victim@example.com" });
  assert.equal(first.headers.get("Location"), `/license/${await fallbackTokenForOrder("order:paddle:txn_first", PK)}`);
  // Orders issued before own tokens existed: the indexed token is used.
  env.LICENSES.data.set("order:paddle:txn_legacy", CLAIM);
  const legacy = await recoverRequest(env, { order: "txn_legacy", email: "victim@example.com" });
  assert.equal(legacy.headers.get("Location"), `/license/${CLAIM}`);

  const wrongEmail = await recoverRequest(env, { order: "txn_second", email: "victim@example.com" });
  const unknown = await recoverRequest(env, { order: "txn_nope", email: "other@example.com" });
  const malformed = await recoverRequest(env, { order: "../x", email: "x" });
  const texts = [];
  for (const r of [wrongEmail, unknown, malformed]) {
    assert.equal(r.status, 404);
    assert.equal(r.headers.get("Location"), null);
    texts.push(await r.text());
  }
  assert.equal(new Set(texts).size, 1, "every failure looks the same");

  const form = await handle(new Request("https://licenses.example/recover"), env, deps);
  assert.equal(form.status, 200);
  assert.match(form.headers.get("Content-Security-Policy"), /form-action 'self'/);
  assert.match(await form.text(), /<form method="post" action="\/recover">/);

  const big = await recoverRequest(env, { order: "txn_second", email: "x".repeat(5000) });
  assert.equal(big.status, 413);
  assert.equal((await handle(new Request("https://licenses.example/recover", { method: "PUT" }), env, deps)).status, 404);
});

test("F8: /recover does the same KV reads for an unknown order as for a known one with the wrong email", async () => {
  for (const provider of [undefined, "paddle"]) {
    const env = makeEnv(undefined, { PROVIDER: provider });
    await webhook(env, transaction("txn_known", "ctm_victim", CLAIM));
    env.LICENSES.data.set("order:paddle:txn_legacy", CLAIM); // issued before own tokens
    env.LICENSES.data.set("order:lemonsqueezy:2002", CLAIM);
    const readsFor = async (order) => {
      // A fresh email each time, so the throttle record is always a miss too.
      const email = `probe-${order}@example.com`;
      env.LICENSES.gets.length = 0;
      const r = await recoverRequest(env, { order, email });
      assert.equal(r.status, 404);
      return env.LICENSES.gets.length;
    };
    const unknownTxn = await readsFor("txn_unknown");
    assert.equal(await readsFor("txn_known"), unknownTxn);
    assert.equal(await readsFor("txn_legacy"), unknownTxn);
    // Three throttle reads (pair, email, order) plus three per provider tried.
    assert.equal(unknownTxn, 3 + 3);
    if (provider === undefined) {
      // Non-txn ids try both providers: 2 x 3 reads whether known or not.
      const unknownOther = await readsFor("9999");
      assert.equal(unknownOther, 3 + 6);
      assert.equal(await readsFor("2002"), unknownOther);
    }
  }
});

// --- L-2 ---------------------------------------------------------------------

test("L-2: concurrent duplicate deliveries issue one licence id under one token", async () => {
  for (const claim of [CLAIM, "short"]) {
    const env = makeEnv("stale");
    const body = transaction("txn_dup", "ctm_victim", claim);
    const statuses = await Promise.all([webhook(env, body), webhook(env, body), webhook(env, body)]);
    assert.deepEqual(statuses.map((r) => r.status), [200, 200, 200]);
    const token = tokenOf(env, "order:paddle:txn_dup");
    const own = await fallbackTokenForOrder("order:paddle:txn_dup", PK);
    const licenceKeys = [...env.LICENSES.data.keys()].filter((k) => k.startsWith("license:")).sort();
    assert.deepEqual(licenceKeys, [...new Set([`license:${own}`, `license:${token}`])].sort(), claim);
    assert.equal(token, claim === CLAIM ? CLAIM : own);
    const expected = await licenseIdForOrder("order:paddle:txn_dup");
    assert.equal(bundleAt(env, token).license.license_id, expected);
    assert.equal(env.LICENSES.data.get(`license:${token}`), env.LICENSES.data.get(`license:${own}`));
    assert.equal(env.LICENSES.data.get("order-license:paddle:txn_dup"), expected);
  }
});

test("L-2: licence ids are per order and stable", async () => {
  const a = await licenseIdForOrder("order:paddle:txn_a");
  assert.equal(a, await licenseIdForOrder("order:paddle:txn_a"));
  assert.notEqual(a, await licenseIdForOrder("order:paddle:txn_b"));
  assert.notEqual(a, await licenseIdForOrder("order:lemonsqueezy:txn_a"));
  assert.match(a, /^lgk_[0-9ABCDEFGHJKMNPQRSTVWXYZ]{26}$/);
});

test("L-2: two orders racing for one claim: exactly one wins it, the other keeps its own token", async () => {
  for (let round = 0; round < 5; round++) {
    // Reads lag (KV-like), so both orders see no licence under the claim.
    const env = makeEnv("stale");
    await Promise.all([
      webhook(env, transaction("txn_a", "ctm_victim", CLAIM)),
      webhook(env, transaction("txn_b", "ctm_other", CLAIM)),
    ]);
    const tokens = { txn_a: tokenOf(env, "order:paddle:txn_a"), txn_b: tokenOf(env, "order:paddle:txn_b") };
    const winners = Object.keys(tokens).filter((id) => tokens[id] === CLAIM);
    assert.equal(winners.length, 1, `round ${round}: ${JSON.stringify(tokens)}`);
    const winner = winners[0];
    assert.equal(env.CLAIMS.rows.size, 1);
    assert.equal(env.CLAIMS.rows.get(CLAIM).order_key, `order:paddle:${winner}`);
    // The claim page shows the winner's licence and only that.
    assert.equal(bundleAt(env, CLAIM).license.license_id, await licenseIdForOrder(`order:paddle:${winner}`));
    for (const [id, email] of [["txn_a", "victim@example.com"], ["txn_b", "other@example.com"]]) {
      const orderKey = `order:paddle:${id}`;
      const own = await fallbackTokenForOrder(orderKey, PK);
      if (id !== winner) assert.equal(tokens[id], own);
      assert.equal(bundleAt(env, own).license.license_id, await licenseIdForOrder(orderKey));
      assert.equal(env.LICENSES.data.get(`order-license:paddle:${id}`), await licenseIdForOrder(orderKey));
      const found = await recoverRequest(env, { order: id, email });
      assert.equal(found.headers.get("Location"), `/license/${own}`);
    }
  }
});

test("L-2: the same order delivered twice, or concurrently, binds the claim once and agrees", async () => {
  const env = makeEnv("stale");
  const body = transaction("txn_same", "ctm_victim", CLAIM);
  await Promise.all([webhook(env, body), webhook(env, body)]);
  assert.equal(tokenOf(env, "order:paddle:txn_same"), CLAIM);
  // A retry after a partial write (order index missing) still finds its own row.
  env.LICENSES.data.delete("order:paddle:txn_same");
  assert.equal((await webhook(env, body)).status, 200);
  assert.equal(tokenOf(env, "order:paddle:txn_same"), CLAIM);
  assert.equal(env.CLAIMS.rows.size, 1);
  assert.equal(await pageHolder(env, CLAIM), "Victim V (victim@example.com)");
});

test("L-2: without the D1 binding, or with D1 failing, no claim is bound and the licence is recoverable", async () => {
  for (const claims of [undefined, fakeD1({ fail: true })]) {
    const env = makeEnv(undefined, { CLAIMS: claims });
    assert.equal((await webhook(env, transaction("txn_nod1", "ctm_victim", CLAIM))).status, 200);
    const own = await fallbackTokenForOrder("order:paddle:txn_nod1", PK);
    assert.equal(tokenOf(env, "order:paddle:txn_nod1"), own);
    assert.equal(env.LICENSES.data.has(`license:${CLAIM}`), false);
    assert.equal(env.LICENSES.data.has(`claim:${CLAIM}`), false, "no racy KV fallback");
    assert.equal(await pageHolder(env, CLAIM), "PENDING");
    const found = await recoverRequest(env, { order: "txn_nod1", email: "victim@example.com" });
    assert.equal(found.status, 303);
    assert.equal(found.headers.get("Location"), `/license/${own}`);
  }
});

// --- R-6 ---------------------------------------------------------------------

test("R-6: /recover allows 5 attempts per email and order id per hour, keyed by an HMAC of the pair", async () => {
  const env = makeEnv();
  await webhook(env, transaction("txn_r", "ctm_victim", CLAIM));
  const statuses = [];
  for (let i = 0; i < 5; i++) {
    statuses.push((await recoverRequest(env, { order: "txn_guess", email: "Victim@Example.com" })).status);
  }
  assert.deepEqual(statuses, [404, 404, 404, 404, 404]);
  // Over the limit, that pair is refused.
  const wrong = await recoverRequest(env, { order: "txn_guess", email: "victim@example.com" });
  assert.equal(wrong.status, 429);
  assert.equal(wrong.headers.get("Retry-After"), "3600");
  // Bogus attempts against the email do not lock the real owner out (audit low finding).
  const owner = await recoverRequest(env, { order: "txn_r", email: "victim@example.com" });
  assert.equal(owner.status, 303);
  // Malformed order ids are not counted at all.
  for (let i = 0; i < 10; i++) await recoverRequest(env, { order: "../bogus", email: "victim@example.com" });
  // Other emails are unaffected; no key or value holds the address.
  assert.equal((await recoverRequest(env, { order: "txn_r", email: "other@example.com" })).status, 404);
  const throttleKeys = [...env.LICENSES.data.keys()].filter((k) => k.startsWith("recover-throttle:"));
  assert.equal(throttleKeys.length, 3);
  for (const key of throttleKeys) {
    assert.match(key, /^recover-throttle:[A-Za-z0-9_-]{43}$/);
    assert.doesNotMatch(env.LICENSES.data.get(key), /@/);
  }
  // An hour later the window resets.
  const saved = deps;
  deps = { ...deps, now: NOW + 3600 * 1000 };
  try {
    assert.equal((await recoverRequest(env, { order: "txn_guess", email: "victim@example.com" })).status, 404);
  } finally {
    deps = saved;
  }
});

test("R-6: one email cannot be tried against many guessed order ids", async () => {
  const env = makeEnv();
  await webhook(env, transaction("txn_mine", "ctm_victim", CLAIM));
  const statuses = [];
  for (let i = 0; i < 16; i++) {
    statuses.push((await recoverRequest(env, { order: `txn_guess${i}`, email: "victim@example.com" })).status);
  }
  // Fresh order ids each time, yet the email cap stops the 16th.
  assert.deepEqual(statuses, [...Array(15).fill(404), 429]);
  assert.equal((await recoverRequest(env, { order: "txn_mine", email: "victim@example.com" })).status, 429);
  // Other emails are unaffected, and the cap lifts after the window.
  assert.equal((await recoverRequest(env, { order: "txn_mine", email: "other@example.com" })).status, 404);
  const saved = deps;
  deps = { ...deps, now: NOW + 3600 * 1000 };
  try {
    assert.equal((await recoverRequest(env, { order: "txn_mine", email: "victim@example.com" })).status, 303);
  } finally {
    deps = saved;
  }
});

test("R-6: one order id cannot be tried against many guessed emails", async () => {
  const env = makeEnv();
  await webhook(env, transaction("txn_mine", "ctm_victim", CLAIM));
  const statuses = [];
  for (let i = 0; i < 16; i++) {
    statuses.push((await recoverRequest(env, { order: "txn_mine", email: `guess${i}@example.com` })).status);
  }
  assert.deepEqual(statuses, [...Array(15).fill(404), 429]);
  // Other order ids are unaffected.
  assert.equal((await recoverRequest(env, { order: "txn_other", email: "guess0@example.com" })).status, 404);
});

test("R-6: a buyer mistyping a few times is not locked out", async () => {
  const env = makeEnv();
  await webhook(env, transaction("txn_mine", "ctm_victim", CLAIM));
  for (const [order, email] of [
    ["txn_mien", "victim@example.com"],
    ["txn_mine", "victim@exmaple.com"],
    ["txn_mine", "vicitm@example.com"],
    ["txn_mien", "victim@example.com"],
  ]) {
    assert.equal((await recoverRequest(env, { order, email })).status, 404);
  }
  assert.equal((await recoverRequest(env, { order: "txn_mine", email: "victim@example.com" })).status, 303);
});

test("R-6: a hit and a miss make the same KV reads; malformed emails are not counted", async () => {
  const env = makeEnv();
  await webhook(env, transaction("txn_t", "ctm_victim", CLAIM));
  const reads = [];
  const get = env.LICENSES.get.bind(env.LICENSES);
  env.LICENSES.get = async (key) => {
    reads.push(key.split(":")[0]);
    return get(key);
  };
  const shape = async (fields) => {
    reads.length = 0;
    await recoverRequest(env, fields);
    return reads.join(",");
  };
  const hit = await shape({ order: "txn_t", email: "victim@example.com" });
  const wrongEmail = await shape({ order: "txn_t", email: "nobody@example.com" });
  const miss = await shape({ order: "txn_missing", email: "victim@example.com" });
  assert.equal(hit, "recover-throttle,recover-email-throttle,recover-order-throttle,order,license,license");
  assert.equal(wrongEmail, hit);
  assert.equal(miss, hit);
  const before = env.LICENSES.data.size;
  assert.equal((await recoverRequest(env, { order: "txn_t", email: "no-at-sign" })).status, 404);
  assert.equal(env.LICENSES.data.size, before);
});

// --- L-3 ---------------------------------------------------------------------

async function issued(env, txn = "txn_paid") {
  await webhook(env, transaction(txn, "ctm_victim", CLAIM));
  return env.LICENSES.data.get(`order-license:paddle:${txn}`);
}

test("L-3: an approved full refund is recorded for revocation with the order's licence id", async () => {
  const env = makeEnv();
  const licenseId = await issued(env);
  const response = await webhook(env, adjustmentEvent("adj_1", "txn_paid"));
  assert.equal(response.status, 200);
  const record = JSON.parse(env.LICENSES.data.get("adjustment:paddle:adj_1"));
  assert.equal(record.license_id, licenseId);
  assert.equal(record.order_id, "txn_paid");
  assert.equal(record.revoke, true);
  assert.equal(record.reinstate, false);
  assert.deepEqual(env.LICENSES.meta.get(`revoke:${licenseId}:adj_1`), record);
  assert.ok(JSON.stringify(record).length < 1024, "fits KV metadata");
});

test("L-3: adjustment.updated overwrites the record; pending, partial and rejected refunds do not revoke", async () => {
  const env = makeEnv();
  const licenseId = await issued(env);
  await webhook(env, adjustmentEvent("adj_2", "txn_paid", { status: "pending_approval" }));
  assert.equal(JSON.parse(env.LICENSES.data.get("adjustment:paddle:adj_2")).revoke, false);
  await webhook(env, adjustmentEvent("adj_2", "txn_paid", { status: "rejected", eventType: "adjustment.updated" }));
  const rejected = JSON.parse(env.LICENSES.data.get(`revoke:${licenseId}:adj_2`));
  assert.equal(rejected.revoke, false);
  assert.equal(rejected.reinstate, true);
  await webhook(env, adjustmentEvent("adj_3", "txn_paid", { type: "partial" }));
  assert.equal(JSON.parse(env.LICENSES.data.get("adjustment:paddle:adj_3")).revoke, false);
});

test("L-3: an older adjustment event delivered late does not overwrite a newer one", async () => {
  const env = makeEnv();
  const licenseId = await issued(env);
  await webhook(env, adjustmentEvent("adj_o", "txn_paid", { eventType: "adjustment.updated", occurredAt: "2026-10-25T00:00:00Z" }));
  await webhook(env, adjustmentEvent("adj_o", "txn_paid", { status: "pending_approval", occurredAt: "2026-10-24T00:00:00Z" }));
  const record = JSON.parse(env.LICENSES.data.get(`revoke:${licenseId}:adj_o`));
  assert.equal(record.status, "approved");
  assert.equal(record.revoke, true);
  // On a tie the terminal status stays.
  await webhook(env, adjustmentEvent("adj_o", "txn_paid", { status: "pending_approval", occurredAt: "2026-10-25T00:00:00Z" }));
  assert.equal(JSON.parse(env.LICENSES.data.get("adjustment:paddle:adj_o")).status, "approved");
  // A newer event still replaces it.
  await webhook(env, adjustmentEvent("adj_o", "txn_paid", { status: "reversed", occurredAt: "2026-10-26T00:00:00Z" }));
  assert.equal(JSON.parse(env.LICENSES.data.get("adjustment:paddle:adj_o")).status, "reversed");
});

test("the Worker signs only with the pinned licence key id", async () => {
  const license = { format: 1, license_id: "lgk_" + "0".repeat(26) };
  assert.equal(LICENSE_KEY_ID, "9f76e21ed03c0482");
  // No override: the test key (1fb2572acef33ca2) is refused.
  await assert.rejects(issueBundle(license, PK), /not the pinned licence key/);
  await assert.rejects(issueBundle(license, PK, { LICENSE_KEY_ID_OVERRIDE: "0123456789abcdef" }), /not the pinned/);
  // The release key id can never be named as the override.
  await assert.rejects(issueBundle(license, PK, { LICENSE_KEY_ID_OVERRIDE: "6a892769c82386b3" }), /refused/);
  const bundle = await issueBundle(license, PK, { LICENSE_KEY_ID_OVERRIDE: "1fb2572acef33ca2" });
  assert.equal(bundle.signature.key_id, "1fb2572acef33ca2");
  // A webhook with no override issues nothing (the order stays retryable).
  const env = makeEnv(undefined, { LICENSE_KEY_ID_OVERRIDE: undefined });
  assert.equal((await webhook(env, transaction("txn_pin", "ctm_victim", CLAIM))).status, 503);
  assert.equal(env.LICENSES.data.get("order:paddle:txn_pin"), undefined);
});

test("L-3: chargebacks revoke and reversed chargebacks reinstate; the list script follows the newest", async () => {
  const env = makeEnv();
  const licenseId = await issued(env);
  const other = await issued(env, "txn_other");
  await webhook(env, adjustmentEvent("adj_cb", "txn_paid", { action: "chargeback", occurredAt: "2026-10-25T00:00:00Z" }));
  await webhook(env, adjustmentEvent("adj_rf", "txn_other", { occurredAt: "2026-10-25T00:00:00Z" }));
  await webhook(env, adjustmentEvent("adj_cbr", "txn_paid", { action: "chargeback_reverse", occurredAt: "2026-10-26T00:00:00Z" }));
  await webhook(env, adjustmentEvent("adj_part", "txn_other", { type: "partial", occurredAt: "2026-10-27T00:00:00Z" }));
  const entries = [...env.LICENSES.meta]
    .filter(([key]) => key.startsWith("revoke:"))
    .map(([name, metadata]) => ({ name, metadata }));
  const first = revocationIds(entries);
  assert.deepEqual(first.ids, [other]);
  assert.equal(first.review.length, 1); // the partial refund
  const keep = "lgk_" + "0".repeat(26);
  const second = revocationIds(entries, [keep, licenseId, "junk"]);
  assert.deepEqual(second.ids, [keep, licenseId, other].sort());
  assert.deepEqual(second.reinstated, [licenseId]);
});

test("L-3: adjustments with a bad signature or a bad id store nothing", async () => {
  const env = makeEnv();
  await issued(env);
  const size = env.LICENSES.data.size;
  assert.equal((await webhook(env, adjustmentEvent("adj_y", "txn_paid"), { sign: false })).status, 401);
  assert.equal((await webhook(env, adjustmentEvent("../bad", "txn_paid"))).status, 200);
  assert.equal(env.LICENSES.data.size, size);
});

test("L-3: orders issued before the index fall back to the stored bundle's licence id", async () => {
  const env = makeEnv();
  const licenseId = await issued(env);
  env.LICENSES.data.delete("order-license:paddle:txn_paid");
  await webhook(env, adjustmentEvent("adj_old", "txn_paid"));
  assert.equal(JSON.parse(env.LICENSES.data.get("adjustment:paddle:adj_old")).license_id, licenseId);
});

test("L-3: Lemon Squeezy order_refunded is recorded the same way", async () => {
  const env = makeEnv(undefined, { PROVIDER: "lemonsqueezy", PRODUCT_IDS: "777" });
  const order = JSON.stringify({
    meta: { event_name: "order_created", custom_data: { lgk_claim: CLAIM } },
    data: { id: "1001", attributes: { status: "paid", user_name: "Ada", user_email: "ada@example.com", first_order_item: { product_id: 777 } } },
  });
  await webhook(env, order, { provider: "lemonsqueezy" });
  const refund = JSON.stringify({
    meta: { event_name: "order_refunded" },
    data: { id: "1001", attributes: { status: "refunded", refunded_at: "2026-10-25T00:00:00Z" } },
  });
  assert.equal((await webhook(env, refund, { provider: "lemonsqueezy" })).status, 200);
  const record = JSON.parse(env.LICENSES.data.get("adjustment:lemonsqueezy:refund-1001"));
  assert.equal(record.revoke, true);
  assert.equal(record.license_id, await licenseIdForOrder("order:lemonsqueezy:1001"));
});

test("the licence page links the key to the desktop app's install link", async () => {
  const env = makeEnv();
  await webhook(env, transaction("txn_link", "ctm_victim", CLAIM, "web"));
  const response = await handle(new Request(`https://licenses.example/license/${CLAIM}`), env, deps);
  const html = await response.text();
  const paste = html.match(/<textarea readonly>(LGK1-[A-Za-z0-9_-]+)<\/textarea>/)[1];
  assert.ok(html.includes(`href="localgatekeys://install-licence/${paste}"`));
  assert.match(response.headers.get("Content-Security-Policy"), /default-src 'none'/);
});

test("a pending licence page has no install link", async () => {
  const env = makeEnv();
  const html = await (await handle(new Request(`https://licenses.example/license/${CLAIM}`), env, deps)).text();
  assert.ok(!html.includes("localgatekeys://"));
});

test("F07-1: a refund that arrives before the licence is issued is recorded under the order's licence id", async () => {
  const env = makeEnv();
  assert.equal((await webhook(env, adjustmentEvent("adj_early", "txn_late"))).status, 200);
  const expected = await licenseIdForOrder("order:paddle:txn_late");
  assert.equal(JSON.parse(env.LICENSES.data.get(`revoke:${expected}:adj_early`)).revoke, true);
  assert.equal(await issued(env, "txn_late"), expected);
});

test("F07-5: a body without Content-Length is cut off at the cap", async () => {
  const env = makeEnv();
  const chunk = new TextEncoder().encode("x".repeat(4096));
  let sent = 0;
  const body = new ReadableStream({
    pull(controller) {
      sent += 1;
      if (sent > 1000) controller.close();
      else controller.enqueue(chunk);
    },
  });
  const request = new Request("https://licenses.example/recover", { method: "POST", body, duplex: "half" });
  assert.equal(request.headers.get("Content-Length"), null);
  assert.equal((await handle(request, env, deps)).status, 413);
  assert.ok(sent < 50, `stopped reading early (${sent} chunks)`);
});

// --- Sales alerts (src/sales-alert.js) ---------------------------------------

// Runs `fn` with a fetch that answers Paddle customer lookups and records ntfy pushes.
async function withAlerts(fn) {
  const sent = [];
  const before = deps;
  deps = {
    ...deps,
    fetch: async (url, init) => {
      if (!url.startsWith("https://ntfy.sh/")) return fakeFetch(url);
      sent.push({ url, title: init.headers.Title, body: init.body });
      return new Response("ok");
    },
  };
  try {
    await fn(sent);
  } finally {
    deps = before;
  }
}

function paidTransaction(id, total, currency) {
  const event = JSON.parse(transaction(id, "ctm_victim", CLAIM));
  event.data.currency_code = currency;
  event.data.details = { totals: { total } };
  return JSON.stringify(event);
}

test("a Paddle sale sends one sales alert with the total, and a retry sends none", async () => {
  await withAlerts(async (sent) => {
    const env = makeEnv(undefined, { SALES_NTFY_TOPIC: "lgk-sales-test" });
    assert.equal((await webhook(env, paidTransaction("txn_sale", "2999", "USD"))).status, 200);
    assert.equal((await webhook(env, paidTransaction("txn_sale", "2999", "USD"))).status, 200);
    assert.deepEqual(sent, [{ url: "https://ntfy.sh/lgk-sales-test", title: "LocalGateKeys Pro sold", body: "Paddle: 29.99 USD" }]);
    assert.equal((await webhook(env, paidTransaction("txn_yen", "4500", "JPY"))).status, 200);
    assert.equal(sent[1].body, "Paddle: 4500 JPY");
    assert.equal((await webhook(env, transaction("txn_bare", "ctm_victim", CLAIM))).status, 200);
    assert.equal(sent[2].body, "Paddle: new purchase");
  });
});

test("a Paddle refund of an issued licence alerts once; pending, unknown-order and repeated ones do not", async () => {
  await withAlerts(async (sent) => {
    const env = makeEnv(undefined, { SALES_NTFY_TOPIC: "t" });
    await webhook(env, transaction("txn_r", "ctm_victim", CLAIM));
    sent.length = 0;
    await webhook(env, adjustmentEvent("adj_r", "txn_r", { status: "pending_approval" }));
    await webhook(env, adjustmentEvent("adj_other", "txn_other_product"));
    assert.equal(sent.length, 0);
    const approved = adjustmentEvent("adj_r", "txn_r", { eventType: "adjustment.updated", occurredAt: "2026-10-24T14:00:00Z" });
    assert.equal((await webhook(env, approved)).status, 200);
    assert.equal((await webhook(env, approved)).status, 200);
    assert.deepEqual(sent, [{ url: "https://ntfy.sh/t", title: "LocalGateKeys Pro refunded", body: "Paddle: order txn_r refunded" }]);
    await webhook(env, adjustmentEvent("adj_cb", "txn_r", { action: "chargeback" }));
    assert.equal(sent[1].title, "LocalGateKeys Pro charged back");
  });
});

test("no topic means no Paddle alert, and a failed alert does not fail the webhook", async () => {
  await withAlerts(async (sent) => {
    assert.equal((await webhook(makeEnv(), paidTransaction("txn_quiet", "2999", "USD"))).status, 200);
    assert.equal(sent.length, 0);
  });
  const before = deps;
  deps = { ...deps, fetch: async (url) => { if (url.startsWith("https://ntfy.sh/")) throw new Error("down"); return fakeFetch(url); } };
  try {
    const env = makeEnv(undefined, { SALES_NTFY_TOPIC: "t" });
    assert.equal((await webhook(env, paidTransaction("txn_down", "2999", "USD"))).status, 200);
    assert.match(tokenOf(env, "order:paddle:txn_down"), TOKEN);
  } finally {
    deps = before;
  }
});

test("concurrent deliveries of one Paddle sale push one alert (W5)", async () => {
  await withAlerts(async (sent) => {
    const env = makeEnv(undefined, { SALES_NTFY_TOPIC: "t" });
    const body = paidTransaction("txn_race", "2999", "USD");
    const [a, b] = await Promise.all([webhook(env, body), webhook(env, body)]);
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    assert.equal(sent.length, 1);
  });
});

test("alerts go through ctx.waitUntil and never hold the webhook response (W4)", async () => {
  const pending = [];
  const ctx = { waitUntil: (p) => pending.push(p) };
  const env = makeEnv(undefined, { SALES_NTFY_TOPIC: "t" });
  const before = deps;
  deps = { ...deps, ctx, fetch: (url) => (url.startsWith("https://ntfy.sh/") ? new Promise(() => {}) : fakeFetch(url)) };
  try {
    const r = await webhook(env, paidTransaction("txn_wait", "2999", "USD"));
    assert.equal(r.status, 200);
    assert.equal(pending.length, 1);
  } finally {
    deps = before;
  }
});

test("an exception inside the Worker answers 503 with Retry-After, not Cloudflare's error page (L1)", async () => {
  const env = makeEnv();
  env.LICENSES.get = async () => {
    throw new Error("KV down");
  };
  const r = await handle(new Request("https://licenses.example/license/" + "a".repeat(43)), env, deps);
  assert.equal(r.status, 503);
  assert.equal(r.headers.get("Retry-After"), "30");
  assert.equal(r.headers.get("Cache-Control"), "no-store");
});

// --- Scan 2026-11-15 F4: a refunded web order's key is no longer handed out ---

const pageOf = (env, token, suffix = "") => handle(new Request(`https://licenses.example/license/${token}${suffix}`), env, deps);

test("F4: after a full refund the licence page, the file and /recover answer 'refunded' instead of the key", async () => {
  const env = makeEnv(undefined, { SUPPORT_EMAIL: "help@example.com" });
  await issued(env, "txn_ref");
  const token = tokenOf(env, "order:paddle:txn_ref");
  assert.equal((await pageOf(env, token)).status, 200);
  // A pending or partial refund changes nothing.
  await webhook(env, adjustmentEvent("adj_p", "txn_ref", { status: "pending_approval" }));
  await webhook(env, adjustmentEvent("adj_part", "txn_ref", { type: "partial" }));
  assert.equal(await pageHolder(env, token), "Victim V (victim@example.com)");
  await webhook(env, adjustmentEvent("adj_p", "txn_ref", { eventType: "adjustment.updated", occurredAt: "2026-10-24T14:00:00Z" }));
  for (const t of [token, await fallbackTokenForOrder("order:paddle:txn_ref", PK)]) {
    const page = await pageOf(env, t);
    assert.equal(page.status, 403);
    const html = await page.text();
    assert.match(html, /This licence was refunded/);
    assert.match(html, /help@example\.com/);
    assert.doesNotMatch(html, /LGK1-|install-licence|lgklicense/);
    const file = await pageOf(env, t, "/file");
    assert.equal(file.status, 403);
    assert.equal(await file.text(), "Revoked\n");
  }
  // /recover still finds the order, and leads to the same answer.
  const found = await recoverRequest(env, { order: "txn_ref", email: "victim@example.com" });
  assert.equal(found.status, 303);
  assert.equal((await handle(new Request(`https://licenses.example${found.headers.get("Location")}`), env, deps)).status, 403);
  // Another order is untouched.
  await issued(env, "txn_kept");
  assert.equal((await pageOf(env, tokenOf(env, "order:paddle:txn_kept"))).status, 200);
});

test("F4: a refund recorded before issue, and a reversed refund or chargeback, follow the newest event", async () => {
  const env = makeEnv();
  await webhook(env, adjustmentEvent("adj_early", "txn_early"));
  await issued(env, "txn_early");
  assert.equal((await pageOf(env, tokenOf(env, "order:paddle:txn_early"))).status, 403);
  // Reversed later: the key is served again.
  await webhook(env, adjustmentEvent("adj_early", "txn_early", { status: "reversed", eventType: "adjustment.updated", occurredAt: "2026-10-25T00:00:00Z" }));
  assert.equal((await pageOf(env, tokenOf(env, "order:paddle:txn_early"))).status, 200);
  // A chargeback revokes; its reversal (a separate adjustment) reinstates.
  await webhook(env, adjustmentEvent("adj_cb", "txn_early", { action: "chargeback", occurredAt: "2026-10-26T00:00:00Z" }));
  assert.equal((await pageOf(env, tokenOf(env, "order:paddle:txn_early"))).status, 403);
  await webhook(env, adjustmentEvent("adj_cbr", "txn_early", { action: "chargeback_reverse", occurredAt: "2026-10-27T00:00:00Z" }));
  assert.equal((await pageOf(env, tokenOf(env, "order:paddle:txn_early"))).status, 200);
});

test("F4: a Lemon Squeezy refund hides the key the same way", async () => {
  const env = makeEnv(undefined, { PROVIDER: "lemonsqueezy" });
  const order = JSON.stringify({
    meta: { event_name: "order_created", custom_data: { lgk_claim: CLAIM } },
    data: { id: "7007", attributes: { status: "paid", user_email: "victim@example.com", user_name: "Victim V", first_order_item: { product_id: "pro_1" } } },
  });
  assert.equal((await webhook(env, order, { provider: "lemonsqueezy" })).status, 200);
  const token = tokenOf(env, "order:lemonsqueezy:7007");
  assert.equal((await pageOf(env, token)).status, 200);
  const refund = JSON.stringify({ meta: { event_name: "order_refunded" }, data: { id: "7007", attributes: { status: "refunded", refunded_at: "2026-10-24T13:00:00Z" } } });
  assert.equal((await webhook(env, refund, { provider: "lemonsqueezy" })).status, 200);
  assert.equal((await pageOf(env, token)).status, 403);
});

// --- Scan 2026-11-15 F6: webhook size cap -----------------------------------

function paddedTransaction(id, bytes) {
  const event = JSON.parse(transaction(id, "ctm_victim", CLAIM));
  event.data.padding = "x".repeat(bytes);
  return JSON.stringify(event);
}

test("F6: a Paddle webhook up to 256 KiB issues; a larger one is 413 and alerts once a day", async () => {
  await withAlerts(async (sent) => {
    const env = makeEnv(undefined, { SALES_NTFY_TOPIC: "t" });
    const big = paddedTransaction("txn_big", 200 * 1024);
    assert.ok(big.length > 64 * 1024);
    assert.equal((await webhook(env, big)).status, 200);
    assert.ok(tokenOf(env, "order:paddle:txn_big"), "issued");
    sent.length = 0;
    const huge = paddedTransaction("txn_huge", 257 * 1024);
    assert.equal((await webhook(env, huge)).status, 413);
    assert.equal((await webhook(env, huge)).status, 413);
    assert.equal(tokenOf(env, "order:paddle:txn_huge"), undefined);
    assert.deepEqual(sent.map((s) => s.title), ["LocalGateKeys webhook refused"]);
    // Other routes keep their own, smaller caps.
    const form = new Request("https://licenses.example/recover", { method: "POST", body: "x".repeat(8 * 1024) });
    assert.equal((await handle(form, env, deps)).status, 413);
  });
});

test("final review L4: a burst of unsigned oversize webhooks pushes once, even while KV reads lag", async () => {
  await withAlerts(async (sent) => {
    const env = makeEnv("stale", { SALES_NTFY_TOPIC: "t" });
    const huge = paddedTransaction("txn_flood", 257 * 1024);
    const statuses = await Promise.all(Array.from({ length: 6 }, () => webhook(env, huge, { sign: false })));
    assert.deepEqual(statuses.map((r) => r.status), Array(6).fill(413));
    assert.deepEqual(sent.map((s) => s.title), ["LocalGateKeys webhook refused"]);
    assert.ok(env.LICENSES.data.has(`alerted:webhook-too-large:paddle:${new Date(NOW).toISOString().slice(0, 10)}`), "marker written");
    // Another isolate (its own binding object) that sees the marker sends nothing either.
    const other = makeEnv(undefined, { SALES_NTFY_TOPIC: "t" });
    for (const [k, v] of env.LICENSES.data) other.LICENSES.data.set(k, v);
    assert.equal((await webhook(other, huge, { sign: false })).status, 413);
    assert.equal(sent.length, 1);
  });
});

test("final review L5: a retry after a delivery that bound the claim and then failed still sends the sale alert, once", async () => {
  await withAlerts(async (sent) => {
    const env = makeEnv(undefined, { SALES_NTFY_TOPIC: "t" });
    const put = env.LICENSES.put.bind(env.LICENSES);
    let failed = false;
    env.LICENSES.put = async (key, value, options) => {
      if (!failed && key.startsWith("order-license:")) {
        failed = true;
        throw new Error("KV 503");
      }
      return put(key, value, options);
    };
    const body = paidTransaction("txn_retry", "2999", "USD");
    assert.equal((await webhook(env, body)).status, 503, "the first delivery fails after binding the claim");
    assert.equal(env.CLAIMS.rows.get(CLAIM).order_key, "order:paddle:txn_retry");
    assert.equal(sent.length, 0);
    assert.equal((await webhook(env, body)).status, 200, "the provider's retry finishes the issue");
    assert.equal(tokenOf(env, "order:paddle:txn_retry"), CLAIM);
    assert.equal(sent.length, 1, "the sale alert is sent by the retry");
    assert.equal((await webhook(env, body)).status, 200);
    assert.equal(sent.length, 1, "and only once per order");
  });
});
