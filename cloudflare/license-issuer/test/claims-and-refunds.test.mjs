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
import { fallbackTokenForOrder, licenseIdForOrder } from "../src/sign.js";
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
    // One throttle read plus three per provider tried.
    assert.equal(unknownTxn, 1 + 3);
    if (provider === undefined) {
      // Non-txn ids try both providers: 2 x 3 reads whether known or not.
      const unknownOther = await readsFor("9999");
      assert.equal(unknownOther, 1 + 6);
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

test("R-6: /recover allows 5 attempts per email per hour, keyed by an HMAC of the email", async () => {
  const env = makeEnv();
  await webhook(env, transaction("txn_r", "ctm_victim", CLAIM));
  const statuses = [];
  for (let i = 0; i < 5; i++) {
    statuses.push((await recoverRequest(env, { order: `txn_guess${i}`, email: "Victim@Example.com" })).status);
  }
  assert.deepEqual(statuses, [404, 404, 404, 404, 404]);
  // Over the limit even the right pair is refused, and the answer says nothing about it.
  const blocked = await recoverRequest(env, { order: "txn_r", email: "victim@example.com" });
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get("Location"), null);
  assert.equal(blocked.headers.get("Retry-After"), "3600");
  const wrong = await recoverRequest(env, { order: "txn_nope", email: "victim@example.com" });
  assert.equal(wrong.status, 429);
  assert.equal(await blocked.text(), await wrong.text());
  // Other emails are unaffected; no key or value holds the address.
  assert.equal((await recoverRequest(env, { order: "txn_r", email: "other@example.com" })).status, 404);
  const throttleKeys = [...env.LICENSES.data.keys()].filter((k) => k.startsWith("recover-throttle:"));
  assert.equal(throttleKeys.length, 2);
  for (const key of throttleKeys) {
    assert.match(key, /^recover-throttle:[A-Za-z0-9_-]{43}$/);
    assert.doesNotMatch(env.LICENSES.data.get(key), /@/);
  }
  // An hour later the window resets.
  const saved = deps;
  deps = { ...deps, now: NOW + 3600 * 1000 };
  try {
    const later = await recoverRequest(env, { order: "txn_r", email: "victim@example.com" });
    assert.equal(later.status, 303);
    assert.equal(later.headers.get("Location"), `/license/${await fallbackTokenForOrder("order:paddle:txn_r", PK)}`);
  } finally {
    deps = saved;
  }
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
  assert.equal(hit, "recover-throttle,order,license,license");
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

test("L-3: adjustments for unknown orders or with a bad signature store nothing", async () => {
  const env = makeEnv();
  assert.equal((await webhook(env, adjustmentEvent("adj_x", "txn_unknown"))).status, 200);
  assert.equal(env.LICENSES.data.size, 0);
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
