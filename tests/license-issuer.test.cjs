// Tests for the Cloudflare licence-issuing Worker (cloudflare/license-issuer).
// KV and the Paddle API are in-memory fakes; nothing reaches the network.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const SRC = path.join(__dirname, "..", "cloudflare", "license-issuer", "src");
const load = (name) => import(pathToFileURL(path.join(SRC, name)).href);
const VECTORS = path.join(__dirname, "vectors", "license");

// TEST ONLY: throwaway Ed25519 key used for the checked-in vectors. It signs nothing real.
const TEST_PRIVATE_PKCS8_B64 = "MC4CAQAwBQYDK2VwBCIEIAbQx1FfuhaeywNI9WhH4kiEiWHlqopq/NpubKWX0HYk";
const privateKey = crypto.createPrivateKey({
  key: Buffer.from(TEST_PRIVATE_PKCS8_B64, "base64"),
  format: "der",
  type: "pkcs8",
});
const publicKey = crypto.createPublicKey(privateKey);
const publicRaw = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
const KEY_ID = crypto.createHash("sha256").update(publicRaw).digest().subarray(0, 8).toString("hex");

const SECRET = "whsec-test";
const NOW = Date.parse("2026-10-15T12:00:00Z");
const CLAIM = "A".repeat(43);

function fakeKv() {
  const data = new Map();
  return {
    data,
    reads: [],
    async get(key, options) {
      this.reads.push({ key, options });
      return data.has(key) ? data.get(key) : null;
    },
    async put(key, value) {
      data.set(key, value);
    },
  };
}

// Test hooks (fixed clock, fake fetch) are injected as `deps`, never through env.
const injectedFetch = new WeakMap();

function makeEnv({ FETCH, ...extra } = {}) {
  const env = {
    LICENSES: fakeKv(),
    LICENSE_PRIVATE_KEY: TEST_PRIVATE_PKCS8_B64,
    WEBHOOK_SECRET: SECRET,
    PADDLE_API_KEY: "pdl_test",
    PRODUCT_IDS: "777,pro_1", // the default lemonEvent / paddleEvent products
    ...extra,
  };
  injectedFetch.set(env, FETCH);
  return env;
}

const depsFor = (env) => ({ now: NOW, fetch: injectedFetch.get(env) });

const hmac = (message) => crypto.createHmac("sha256", SECRET).update(message).digest("hex");

async function send(env, pathname, { method = "POST", body = "", headers = {} } = {}) {
  const { handle } = await load("index.js");
  const init = { method, headers };
  if (method === "POST") init.body = body;
  return handle(new Request(`https://licenses.example${pathname}`, init), env, depsFor(env));
}

function lemonEvent({
  id = "1001",
  status = "paid",
  name = "Ada Lovelace",
  email = "ada@example.com",
  claim = CLAIM,
  testMode = false,
  productId = 777,
} = {}) {
  return JSON.stringify({
    meta: { event_name: "order_created", test_mode: testMode, custom_data: claim === null ? {} : { lgk_claim: claim } },
    data: { id, attributes: { status, user_name: name, user_email: email, first_order_item: { product_id: productId } } },
  });
}

const lemon = (env, body, signature = hmac(body)) =>
  send(env, "/webhooks/lemonsqueezy", { body, headers: { "X-Signature": signature } });

function paddleEvent({ id = "txn_1", customer = "ctm_1", claim = CLAIM, type = "transaction.completed", productId = "pro_1" } = {}) {
  return JSON.stringify({
    event_type: type,
    data: { id, customer_id: customer, custom_data: { lgk_claim: claim }, items: [{ price: { product_id: productId } }] },
  });
}

function paddle(env, body, { ts = Math.floor(NOW / 1000), signature } = {}) {
  const h1 = signature ?? hmac(`${ts}:${body}`);
  return send(env, "/webhooks/paddle", { body, headers: { "Paddle-Signature": `ts=${ts};h1=${h1}` } });
}

function paddleFetch(customer, calls = []) {
  return async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ data: customer }), { status: 200 });
  };
}

function storedBundle(env, token = CLAIM) {
  return JSON.parse(env.LICENSES.data.get(`license:${token}`));
}

function verifies(bundle) {
  const message = Buffer.from(canonical(bundle.license), "utf8");
  return crypto.verify(null, message, publicKey, Buffer.from(bundle.signature.signature, "base64"));
}

// Independent canonicalizer (test side) so the Worker's is not checked against itself.
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

test("Lemon Squeezy: valid order stores a verifiable licence under the claimed token", async () => {
  const env = makeEnv();
  const response = await lemon(env, lemonEvent());
  assert.equal(response.status, 200);
  const bundle = storedBundle(env);
  assert.deepEqual(Object.keys(bundle.license).sort(), [
    "edition",
    "email",
    "format",
    "issued_at",
    "license_id",
    "name",
    "updates_until",
  ]);
  assert.equal(bundle.license.name, "Ada Lovelace");
  assert.equal(bundle.license.edition, "pro");
  assert.equal(bundle.license.format, 1);
  assert.equal(bundle.license.issued_at, "2026-10-15");
  assert.equal(bundle.license.updates_until, "9999-12-31");
  assert.match(bundle.license.license_id, /^lgk_[0-9ABCDEFGHJKMNPQRSTVWXYZ]{26}$/);
  assert.equal(bundle.signature.alg, "Ed25519");
  assert.equal(bundle.signature.key_id, KEY_ID);
  assert.ok(verifies(bundle));
  assert.equal(env.LICENSES.data.get("order:lemonsqueezy:1001"), CLAIM);
});

test("Lemon Squeezy: bad or missing signature is 401 and stores nothing", async () => {
  const env = makeEnv();
  assert.equal((await lemon(env, lemonEvent(), "00".repeat(32))).status, 401);
  assert.equal((await lemon(env, lemonEvent(), "not-hex")).status, 401);
  assert.equal((await send(env, "/webhooks/lemonsqueezy", { body: lemonEvent() })).status, 401);
  assert.equal(env.LICENSES.data.size, 0);
});

test("Lemon Squeezy: other events and unpaid orders are ignored with 200", async () => {
  const env = makeEnv();
  assert.equal((await lemon(env, lemonEvent({ status: "pending" }))).status, 200);
  const other = JSON.stringify({ meta: { event_name: "order_refunded" }, data: { id: "5", attributes: {} } });
  assert.equal((await lemon(env, other)).status, 200);
  assert.equal(env.LICENSES.data.size, 0);
});

test("malformed JSON is 400 and oversized body is 413", async () => {
  const env = makeEnv();
  const junk = "{not json";
  assert.equal((await lemon(env, junk)).status, 400);
  const big = JSON.stringify({ pad: "x".repeat(70 * 1024) });
  assert.equal((await lemon(env, big)).status, 413);
});

test("duplicate order returns 200 and keeps one licence under the same token", async () => {
  const env = makeEnv();
  await lemon(env, lemonEvent());
  const before = env.LICENSES.data.get(`license:${CLAIM}`);
  const keys = env.LICENSES.data.size;
  assert.equal((await lemon(env, lemonEvent({ claim: "B".repeat(43) }))).status, 200);
  assert.equal(env.LICENSES.data.size, keys);
  assert.equal(env.LICENSES.data.get(`license:${CLAIM}`), before);
});

test("claim that is malformed or already used falls back to a fresh random token", async () => {
  const env = makeEnv();
  await lemon(env, lemonEvent({ id: "1", claim: "short" }));
  const fresh = env.LICENSES.data.get("order:lemonsqueezy:1");
  assert.match(fresh, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(env.LICENSES.data.has(`license:${fresh}`));

  await lemon(env, lemonEvent({ id: "2" }));
  await lemon(env, lemonEvent({ id: "3" })); // same claim again
  const third = env.LICENSES.data.get("order:lemonsqueezy:3");
  assert.notEqual(third, CLAIM);
  assert.equal(env.LICENSES.data.get("order:lemonsqueezy:2"), CLAIM);
});

test("Paddle: valid event fetches the customer and issues a licence", async () => {
  const calls = [];
  const env = makeEnv({ FETCH: paddleFetch({ email: "grace@example.com", name: "Grace Hopper" }, calls) });
  const response = await paddle(env, paddleEvent());
  assert.equal(response.status, 200);
  assert.equal(calls[0].url, "https://api.paddle.com/customers/ctm_1");
  assert.equal(calls[0].init.headers.Authorization, "Bearer pdl_test");
  const bundle = storedBundle(env);
  assert.equal(bundle.license.email, "grace@example.com");
  assert.equal(bundle.license.name, "Grace Hopper");
  assert.ok(verifies(bundle));
});

test("Paddle: empty customer name falls back to the email", async () => {
  const env = makeEnv({ FETCH: paddleFetch({ email: "no.name@example.com", name: null }) });
  await paddle(env, paddleEvent());
  assert.equal(storedBundle(env).license.name, "no.name@example.com");
});

test("Paddle: bad signature and replayed timestamp are 401", async () => {
  const calls = [];
  const env = makeEnv({ FETCH: paddleFetch({ email: "g@example.com", name: "G" }, calls) });
  const body = paddleEvent();
  assert.equal((await paddle(env, body, { signature: "00".repeat(32) })).status, 401);
  const stale = Math.floor(NOW / 1000) - 301;
  assert.equal((await paddle(env, body, { ts: stale })).status, 401);
  const future = Math.floor(NOW / 1000) + 301;
  assert.equal((await paddle(env, body, { ts: future })).status, 401);
  assert.equal((await paddle(env, body, { ts: Math.floor(NOW / 1000) - 299 })).status, 200);
  assert.equal(calls.length, 1);
});

test("Paddle: other events are ignored; duplicate order does not refetch or reissue", async () => {
  const calls = [];
  const env = makeEnv({ FETCH: paddleFetch({ email: "g@example.com", name: "G" }, calls) });
  assert.equal((await paddle(env, paddleEvent({ type: "transaction.created" }))).status, 200);
  assert.equal(env.LICENSES.data.size, 0);
  await paddle(env, paddleEvent());
  const size = env.LICENSES.data.size;
  assert.equal((await paddle(env, paddleEvent({ claim: "C".repeat(43) }))).status, 200);
  assert.equal(env.LICENSES.data.size, size);
  assert.equal(calls.length, 1);
});

test("Paddle: customer lookup failure returns 500 so the provider retries, storing nothing", async () => {
  const env = makeEnv({ FETCH: async () => new Response("nope", { status: 500 }) });
  const { handle } = await load("index.js");
  const body = paddleEvent();
  const ts = Math.floor(NOW / 1000);
  const request = new Request("https://licenses.example/webhooks/paddle", {
    method: "POST",
    body,
    headers: { "Paddle-Signature": `ts=${ts};h1=${hmac(`${ts}:${body}`)}` },
  });
  await assert.rejects(() => handle(request, env, depsFor(env)));
  assert.equal(env.LICENSES.data.size, 0);
});

test("key_id is derived from the private key; a stray LICENSE_KEY_ID is ignored", async () => {
  const env = makeEnv({ LICENSE_KEY_ID: "deadbeefdeadbeef" });
  await lemon(env, lemonEvent());
  assert.equal(storedBundle(env).signature.key_id, KEY_ID);
});

async function rejectsWebhook(env, body) {
  const { handle } = await load("index.js");
  const request = new Request("https://licenses.example/webhooks/lemonsqueezy", {
    method: "POST",
    body,
    headers: { "X-Signature": hmac(body) },
  });
  await assert.rejects(() => handle(request, env, depsFor(env)));
  assert.equal(env.LICENSES.data.size, 0);
}

test("an unusable private key fails the webhook and stores nothing", async () => {
  await rejectsWebhook(makeEnv({ LICENSE_PRIVATE_KEY: "AAAA" }), lemonEvent());
});

test("paid Lemon Squeezy order without a usable email throws so the provider retries", async () => {
  await rejectsWebhook(makeEnv(), lemonEvent({ email: "" }));
});

test("Lemon Squeezy test_mode orders are ignored unless ALLOW_TEST_MODE=1", async () => {
  const env = makeEnv();
  assert.equal((await lemon(env, lemonEvent({ testMode: true }))).status, 200);
  assert.equal(env.LICENSES.data.size, 0);
  const allowed = makeEnv({ ALLOW_TEST_MODE: "1" });
  await lemon(allowed, lemonEvent({ testMode: true }));
  assert.ok(allowed.LICENSES.data.has(`license:${CLAIM}`));
});

test("PRODUCT_IDS filters Lemon Squeezy and Paddle orders", async () => {
  const env = makeEnv({ PRODUCT_IDS: "777, pro_1", FETCH: paddleFetch({ email: "g@example.com", name: "G" }) });
  await lemon(env, lemonEvent({ id: "1", productId: 999, claim: "D".repeat(43) }));
  await paddle(env, paddleEvent({ id: "t1", productId: "pro_other", claim: "E".repeat(43) }));
  assert.equal(env.LICENSES.data.size, 0);
  await lemon(env, lemonEvent({ id: "2", productId: 777 }));
  await paddle(env, paddleEvent({ id: "t2", productId: "pro_1", claim: "F".repeat(43) }));
  assert.ok(env.LICENSES.data.has(`license:${CLAIM}`));
  assert.ok(env.LICENSES.data.has(`license:${"F".repeat(43)}`));
});

// Fails closed: an unset or empty PRODUCT_IDS must never mean "every product".
for (const [label, extra] of [
  ["unset", { PRODUCT_IDS: undefined }],
  ["empty", { PRODUCT_IDS: "" }],
  ["only separators", { PRODUCT_IDS: " , ," }],
]) {
  test(`PRODUCT_IDS ${label}: signed webhooks are 500 (provider retries), logged, and issue nothing`, async () => {
    const env = makeEnv({ ...extra, FETCH: paddleFetch({ email: "g@example.com", name: "G" }) });
    if (extra.PRODUCT_IDS === undefined) delete env.PRODUCT_IDS;
    const logged = [];
    const original = console.error;
    console.error = (...args) => logged.push(args.join(" "));
    try {
      const lemonResponse = await lemon(env, lemonEvent());
      const paddleResponse = await paddle(env, paddleEvent());
      assert.equal(lemonResponse.status, 500);
      assert.equal(paddleResponse.status, 500);
      // Signature verification still runs first: a forged request is 401, not 500.
      assert.equal((await lemon(env, lemonEvent(), "00".repeat(32))).status, 401);
    } finally {
      console.error = original;
    }
    assert.equal(env.LICENSES.data.size, 0);
    assert.equal(logged.length, 2);
    assert.ok(logged.every((line) => line.includes("PRODUCT_IDS")));
  });
}

test("parsers reject every product when PRODUCT_IDS is unset or empty, and accept a match", async () => {
  const { parseLemonSqueezy, parsePaddle } = await load("providers.js");
  const lemonOrder = JSON.parse(lemonEvent());
  const paddleOrder = JSON.parse(paddleEvent());
  for (const env of [{}, { PRODUCT_IDS: "" }, { PRODUCT_IDS: " , " }]) {
    assert.equal(parseLemonSqueezy(lemonOrder, env), null);
    assert.equal(parsePaddle(paddleOrder, env), null);
  }
  assert.equal(parseLemonSqueezy(lemonOrder), null); // default env is {}
  assert.equal(parsePaddle(paddleOrder), null);
  assert.equal(parseLemonSqueezy(lemonOrder, { PRODUCT_IDS: "777" }).orderId, "1001");
  assert.equal(parsePaddle(paddleOrder, { PRODUCT_IDS: "x, pro_1" }).orderId, "txn_1");
  assert.equal(parsePaddle(paddleOrder, { PRODUCT_IDS: "pro_10" }), null);
});

test("license page: pending, ready, escaping, headers and file download", async () => {
  const env = makeEnv();
  const pending = await send(env, `/license/${CLAIM}`, { method: "GET" });
  assert.equal(pending.status, 200);
  const pendingHtml = await pending.text();
  assert.ok(pendingHtml.includes(`content="5;url=/license/${CLAIM}?t=${NOW / 1000}"`));
  assert.equal(pending.headers.get("Cache-Control"), "no-store");
  assert.ok(pendingHtml.includes("usually within a minute"));
  // A cached "not found" would hold the buyer on this page; use KV's shortest cache.
  assert.deepEqual(env.LICENSES.reads.at(-1), { key: `license:${CLAIM}`, options: { cacheTtl: 30 } });

  await lemon(env, lemonEvent({ name: '<script>alert(1)</script> "Q"', email: "x@example.com" }));
  const ready = await send(env, `/license/${CLAIM}`, { method: "GET" });
  const html = await ready.text();
  assert.equal(ready.status, 200);
  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script&gt;"));
  assert.match(html, /LGK1-[A-Za-z0-9_-]+/);
  assert.ok(html.includes(`/license/${CLAIM}/file`));
  assert.equal(ready.headers.get("Content-Security-Policy"), "default-src 'none'; style-src 'unsafe-inline'");
  assert.equal(ready.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(ready.headers.get("Referrer-Policy"), "no-referrer");
  assert.equal(ready.headers.get("Access-Control-Allow-Origin"), null);

  const file = await send(env, `/license/${CLAIM}/file`, { method: "GET" });
  assert.equal(file.headers.get("Content-Type"), "application/json");
  assert.equal(file.headers.get("Content-Disposition"), 'attachment; filename="LocalGateKeys-Pro.lgklicense"');
  assert.deepEqual(JSON.parse(await file.text()), storedBundle(env));
});

test("license page names the holder once when the name is the email", async () => {
  const same = makeEnv();
  await lemon(same, lemonEvent({ name: "buyer@example.com", email: "buyer@example.com" }));
  const sameHtml = await (await send(same, `/license/${CLAIM}`, { method: "GET" })).text();
  assert.ok(sameHtml.includes("<p>Licensed to buyer@example.com.</p>"));

  const named = makeEnv();
  await lemon(named, lemonEvent({ name: "Ada Buyer", email: "ada@example.com" }));
  const namedHtml = await (await send(named, `/license/${CLAIM}`, { method: "GET" })).text();
  assert.ok(namedHtml.includes("<p>Licensed to Ada Buyer (ada@example.com).</p>"));
});

test("the LGK1 paste text decodes to the stored bundle", async () => {
  const env = makeEnv();
  await lemon(env, lemonEvent());
  const html = await (await send(env, `/license/${CLAIM}`, { method: "GET" })).text();
  const paste = /LGK1-[A-Za-z0-9_-]+/.exec(html)[0];
  const decoded = Buffer.from(paste.slice(5), "base64url").toString("utf8");
  assert.equal(decoded, canonical(storedBundle(env)));
});

test("unknown routes, methods and malformed tokens are 404", async () => {
  const env = makeEnv();
  assert.equal((await send(env, "/", { method: "GET" })).status, 404);
  assert.equal((await send(env, "/license/short", { method: "GET" })).status, 404);
  assert.equal((await send(env, `/license/${CLAIM}/file`, { method: "GET" })).status, 404);
  assert.equal((await send(env, "/webhooks/other", { body: "{}" })).status, 404);
  assert.equal((await send(env, "/webhooks/paddle", { method: "GET" })).status, 404);
  assert.equal((await send(makeEnv({ PROVIDER: "paddle" }), "/webhooks/lemonsqueezy", { body: "{}" })).status, 404);
});

test("cross-language vector: fixed licence with a non-ASCII name is signed deterministically", async () => {
  const sign = await load("sign.js");
  assert.equal(sign.newLicenseId(new Uint8Array(16)), "lgk_" + "0".repeat(26));
  assert.equal(sign.newLicenseId(new Uint8Array(16).fill(255)), "lgk_" + "Z".repeat(25) + "W");

  const license = sign.buildLicense({
    name: "Zoë Müller 山田",
    email: "zoe@example.com",
    issuedAt: "2026-10-15",
    licenseId: "lgk_0123456789ABCDEFGHJKMNPQRS",
  });
  assert.equal(license.updates_until, "9999-12-31");
  const key = await sign.importPrivateKey(TEST_PRIVATE_PKCS8_B64);
  const bundle = await sign.signLicense(license, key, KEY_ID);
  assert.ok(verifies(bundle));
  assert.equal(await sign.keyIdForPublic(publicRaw), KEY_ID);
  assert.equal(sign.canonicalJson(bundle), canonical(bundle));

  const fileText = `${JSON.stringify(bundle, null, 2)}\n`;
  fs.mkdirSync(VECTORS, { recursive: true });
  fs.writeFileSync(path.join(VECTORS, "worker-issued.lgklicense"), fileText, "utf8");
  fs.writeFileSync(path.join(VECTORS, "worker-public-key.txt"), `${publicRaw.toString("base64")}\n`, "utf8");
});

function pendingAt(env, offsetSeconds, t = NOW / 1000 - offsetSeconds) {
  return send(env, `/license/${CLAIM}?t=${t}`, { method: "GET" });
}

test("pending page keeps the original start time in later refreshes", async () => {
  const env = makeEnv();
  const html = await (await pendingAt(env, 60)).text();
  assert.ok(html.includes(`?t=${NOW / 1000 - 60}"`));
  assert.ok(html.includes("http-equiv=\"refresh\""));
});

test("pending page gives up after 10 minutes and names the support address, escaped", async () => {
  const env = makeEnv({ SUPPORT_EMAIL: 'help@example.com"><b>x' });
  const justBefore = await (await pendingAt(env, 600)).text();
  assert.ok(justBefore.includes("http-equiv"));
  const late = await (await pendingAt(env, 601)).text();
  assert.ok(!late.includes("http-equiv"));
  assert.ok(late.includes("This is taking longer than expected"));
  assert.ok(late.includes("with your order number"));
  assert.ok(late.includes("help@example.com&quot;&gt;&lt;b&gt;x"));
  assert.ok(!late.includes("<b>x"));
  const noEmail = await (await pendingAt(makeEnv(), 601)).text();
  assert.ok(noEmail.includes("contact support with your order number"));
});

test("pending page ignores a malformed or future start time", async () => {
  const env = makeEnv();
  for (const t of ["abc", "-5", "1e3", String(NOW / 1000 + 3600), ""]) {
    const html = await (await pendingAt(env, 0, t)).text();
    assert.ok(html.includes("http-equiv"), t);
    assert.ok(!html.includes("taking longer"), t);
  }
});

test("a licence that arrives late is still shown after the give-up point", async () => {
  const env = makeEnv();
  await lemon(env, lemonEvent());
  const html = await (await pendingAt(env, 3600)).text();
  assert.match(html, /LGK1-[A-Za-z0-9_-]+/);
});

test("env carries no test hooks: default export works with real clock and only bindings/vars", async () => {
  const { default: worker } = await load("index.js");
  const env = makeEnv();
  assert.ok(!("NOW" in env) && !("FETCH" in env));
  const response = await worker.fetch(new Request(`https://licenses.example/license/${CLAIM}`), env);
  assert.equal(response.status, 200);
  assert.ok((await response.text()).includes("?t="));
});
