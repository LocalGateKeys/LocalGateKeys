/* Service worker: classify_site_browser (Verified site / lookalike guard).
 * The broker computes the verdict with the saved origins inside the app; the worker forwards
 * only the page origin, passes on a cleaned verdict and, when the app cannot answer (locked,
 * older app), falls back to its own check that needs no saved origins (mixed-script hosts). */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const EXT = path.join(__dirname, "..", "..", "browser-extension");
const read = name => fs.readFileSync(path.join(EXT, name), "utf8");
const PSL = JSON.parse(read("psl-min.json"));

function harness(native, { url = "https://example.test/login", active = true, lookalike = true, senderOrigin } = {}) {
  let listener; const calls = []; const fetched = []; const id = "testextension";
  const origin = new URL(url).origin;
  const frames = { 0: { documentId: "doc-top", url, documentLifecycle: "active", errorOccurred: false, parentFrameId: -1 } };
  const chrome = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: {
      id, getManifest: () => ({ version: "0.4.12", permissions: [] }), getURL: p => `chrome-extension://${id}/${p}`,
      onMessage: { addListener: f => listener = f },
      sendNativeMessage: (host, req) => { calls.push(req); return Promise.resolve(typeof native === "function" ? native(req) : { ...native }); },
    },
    webNavigation: { getFrame: async ({ frameId }) => frames[frameId], onDOMContentLoaded: { addListener() {} }, onCompleted: { addListener() {} }, onHistoryStateUpdated: { addListener() {} } },
    tabs: { get: async () => ({ active, discarded: false }), sendMessage: () => Promise.resolve() },
  };
  const fetch = async target => {
    fetched.push(String(target));
    if (String(target).endsWith("/psl-min.json")) return { ok: true, json: async () => PSL };
    return { ok: false };
  };
  const context = vm.createContext({ chrome, URL, Set, Map, Promise, setTimeout, clearTimeout, Uint8Array, btoa, fetch });
  vm.runInContext(read("api.js"), context);
  if (lookalike) vm.runInContext(read("lookalike.js"), context);
  vm.runInContext(read("background.js"), context);
  const sender = { id, tab: { id: 8 }, frameId: 0, documentId: "doc-top", url, ...(senderOrigin === undefined ? {} : { origin: senderOrigin }) };
  const send = req => new Promise(resolve => listener({ origin, operation_id: "op-1", ...req }, sender, r => resolve(JSON.parse(JSON.stringify(r)))));
  return { calls, fetched, send };
}

test("classify_site_browser sends only the page origin and context to the app", async () => {
  const h = harness({ ok: true, kind: "exact", reason: "same-origin" });
  const r = await h.send({ type: "classify_site_browser", saved: ["https://evil.test"], username: "alice" });
  assert.deepEqual(r, { ok: true, kind: "exact", reason: "same-origin" });
  assert.equal(h.calls.length, 1);
  const call = h.calls[0];
  assert.equal(call.action, "classify_site_browser");
  assert.equal(call.origin, "https://example.test");
  assert.equal(call.saved, undefined);
  assert.equal(call.username, undefined);
  assert.equal(call.password, undefined);
});

test("classify_site_browser also answers for a background tab (no active-tab requirement)", async () => {
  const h = harness({ ok: true, kind: "related", reason: "same-site" }, { active: false });
  const r = await h.send({ type: "classify_site_browser" });
  assert.deepEqual(r, { ok: true, kind: "related", reason: "same-site" });
});

test("a lookalike verdict keeps the imitated host and pair id, and drops anything else", async () => {
  const pair = "0123456789abcdef0123456789abcdef";
  const h = harness({ ok: true, kind: "lookalike", reason: "other-suffix", matched: "www.amazon.com", pair,
    saved: ["https://bank.test"], extra: "x" });
  const r = await h.send({ type: "classify_site_browser" });
  assert.deepEqual(r, { ok: true, kind: "lookalike", reason: "other-suffix", matched: "www.amazon.com", pair });
  const bad = harness({ ok: true, kind: "lookalike", reason: "homoglyph", matched: "x".repeat(300), pair: "nothex" });
  assert.deepEqual(await bad.send({ type: "classify_site_browser" }), { ok: true, kind: "lookalike", reason: "homoglyph", matched: null });
});

test("an unknown verdict kind from the app is not passed on", async () => {
  const h = harness({ ok: true, kind: "trusted", reason: "x" });
  const r = await h.send({ type: "classify_site_browser" });
  assert.equal(r.kind, undefined);
  assert.equal(r.unchecked, true);
});

test("locked vault: a mixed-script host is still a lookalike, checked in the extension", async () => {
  const h = harness({ ok: true, locked: true }, { url: "https://xn--bnk-6cd.test/login" });
  const r = await h.send({ type: "classify_site_browser" });
  assert.deepEqual(r, { ok: true, kind: "lookalike", reason: "mixed-script", matched: null, local: true });
  assert.ok(h.fetched.includes("chrome-extension://testextension/psl-min.json"), "the bundled suffix list is read");
});

test("locked vault on a plain host: no state, nothing invented", async () => {
  const h = harness({ ok: true, locked: true });
  assert.deepEqual(await h.send({ type: "classify_site_browser" }), { ok: true, locked: true, unchecked: true });
  const old = harness({ ok: false, error: "unsupported_action" });
  assert.deepEqual(await old.send({ type: "classify_site_browser" }), { ok: true, locked: false, unchecked: true });
});

test("without lookalike.js loaded the worker still answers (no local check)", async () => {
  const h = harness({ ok: true, locked: true }, { url: "https://xn--bnk-6cd.test/login", lookalike: false });
  assert.deepEqual(await h.send({ type: "classify_site_browser" }), { ok: true, locked: true, unchecked: true });
});

// Carry T5b: Safari asks the app (SafariSaveService.siteVerdict) for the site check.
async function runSafari(url, native) {
  let listener; const calls = []; const id = "testextension";
  const chrome = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: { id, getManifest: () => ({ version: "0.4.12" }), getURL: p => `safari-web-extension://${id}/${p}`,
      onMessage: { addListener: f => listener = f },
      sendNativeMessage: (app, message) => { calls.push({ app, message: { ...message } }); return Promise.resolve(native(message)); } },
    webNavigation: { getFrame: async () => ({ url, errorOccurred: false, parentFrameId: -1 }) },
    tabs: { onUpdated: { addListener() {} }, onRemoved: { addListener() {} } },
  };
  const fetch = async target => ({ ok: true, json: async () => (String(target).endsWith("/psl-min.json") ? PSL : {}) });
  const context = vm.createContext({ chrome, URL, Set, Map, Promise, setTimeout, clearTimeout, Uint8Array, crypto: globalThis.crypto, fetch });
  vm.runInContext(read("api.js"), context);
  vm.runInContext(read("lookalike.js"), context);
  vm.runInContext(read("background-safari.js"), context);
  const sender = { id, tab: { id: 3 }, frameId: 0, url };
  const r = await new Promise(resolve => listener({ type: "classify_site_browser", origin: new URL(url).origin, operation_id: "op-1", username: "alice", saved: ["https://evil.test"] }, sender, v => resolve(JSON.parse(JSON.stringify(v)))));
  return { r, calls };
}

test("background-safari asks the app for the site verdict and sends only the page origin", async () => {
  const pair = "0123456789abcdef0123456789abcdef";
  const app = { status: "unavailable", site: "lookalike", site_reason: "other-suffix", site_matched: "paypal.com", site_pair: pair };
  const fake = await runSafari("https://paypal.net/login", () => app);
  assert.deepEqual(fake.r, { ok: true, kind: "lookalike", reason: "other-suffix", matched: "paypal.com", pair });
  assert.deepEqual(fake.calls, [{ app: "app.localgatekeys.app", message: { action: "classify", origin: "https://paypal.net" } }]);
  const verified = await runSafari("https://example.test/login", () => ({ status: "unavailable", site: "exact", site_reason: "same-origin" }));
  assert.deepEqual(verified.r, { ok: true, kind: "exact", reason: "same-origin", matched: null });
  // An app verdict wins over the local check, and its fields are cleaned before content.js sees them.
  const odd = await runSafari("https://xn--bnk-6cd.test/login", () => ({ site: "lookalike", site_reason: "x".repeat(40), site_matched: "bad host", site_pair: "NOT-HEX" }));
  assert.deepEqual(odd.r, { ok: true, kind: "lookalike", reason: "x".repeat(32), matched: null });
});

test("background-safari falls back to the local mixed-script check when the app has no verdict", async () => {
  for (const reply of [{ status: "unavailable" }, { site: "maybe" }, null, undefined]) {
    const mixed = await runSafari("https://xn--bnk-6cd.test/login", () => reply);
    assert.deepEqual(mixed.r, { ok: true, kind: "lookalike", reason: "mixed-script", matched: null, local: true }, String(reply));
    assert.equal(mixed.calls.length, 1, "the app was asked first");
    const plain = await runSafari("https://example.test/login", () => reply);
    assert.deepEqual(plain.r, { ok: true, unchecked: true });
  }
  const broken = await runSafari("https://xn--bnk-6cd.test/login", () => { throw new Error("no handler"); });
  assert.equal(broken.r.reason, "mixed-script");
});

test("new_site_username_browser forwards only the username and answers a bare yes/no", async () => {
  const h = harness({ ok: true, elsewhere: true, site: "https://bank.test" });
  const r = await h.send({ type: "new_site_username_browser", username: "alice", password: "pw", user_gesture: true });
  assert.deepEqual(r, { ok: true, elsewhere: true });
  assert.equal(h.calls[0].username, "alice");
  assert.equal(h.calls[0].password, undefined);
  assert.equal(h.calls[0].user_gesture, true);
  const empty = harness({ ok: true, elsewhere: true });
  assert.deepEqual(await empty.send({ type: "new_site_username_browser", username: "" }), { ok: false, error: "invalid_credential" });
  assert.equal(empty.calls.length, 0);
  const odd = harness({ ok: true, elsewhere: "yes" });
  assert.deepEqual(await odd.send({ type: "new_site_username_browser", username: "alice" }), { ok: true, elsewhere: false });
});

test("R1: lookalike_confirmed is forwarded only on the two save ops, and only as true", async () => {
  const h = harness({ ok: true, status: "created" });
  await h.send({ type: "save_pending_browser", pending_token: "tok-1", user_gesture: true, gesture_nonce: "ab".repeat(16), lookalike_confirmed: true });
  assert.equal(h.calls[0].lookalike_confirmed, true);
  await h.send({ type: "save_browser", username: "a", password: "p", user_gesture: true, gesture_nonce: "ab".repeat(16), lookalike_confirmed: "yes" });
  assert.equal(h.calls[1].lookalike_confirmed, undefined);
  await h.send({ type: "check_browser", username: "a", password: "p", lookalike_confirmed: true });
  assert.equal(h.calls[2].lookalike_confirmed, undefined);
  const refusal = { ok: false, error: "lookalike_site", kind: "lookalike", reason: "homoglyph", matched: "example.com" };
  const r = harness(refusal);
  assert.deepEqual(await r.send({ type: "save_pending_browser", pending_token: "tok-1", user_gesture: true, gesture_nonce: "ab".repeat(16) }), refusal);
});

test("fill_grant_browser (AI agent sign-in) forwards only origin, context and the page URL", async () => {
  const h = harness({ ok: true, agent: true, choices: [{ entry_id: "e1", username: "u", label: "L" }], grant: "g" },
    { url: "https://login.example.test/signin?x=1" });
  const r = await h.send({ type: "fill_grant_browser", url: "https://login.example.test/signin?x=1" });
  assert.equal(r.ok, true);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].action, "fill_grant_browser");
  assert.equal(h.calls[0].origin, "https://login.example.test");
  assert.equal(h.calls[0].url, "https://login.example.test/signin?x=1");
  assert.equal(h.calls[0].user_gesture, false, "an agent fill is never a user gesture");
  assert.equal(typeof h.calls[0].context, "string");
});

test("fill_grant_browser needs the active tab", async () => {
  const h = harness({ ok: true }, { active: false });
  const r = await h.send({ type: "fill_grant_browser" });
  assert.equal(r.ok, false);
  assert.equal(h.calls.length, 0);
});

test("an opaque-origin (sandboxed) sender is refused for fill, save and passkeys; a matching sender.origin passes", async () => {
  for (const type of ["begin_browser", "save_browser", "passkey_get_browser", "fill_grant_browser"]) {
    for (const senderOrigin of ["null", "https://other.test"]) {
      const h = harness({ ok: true }, { senderOrigin });
      const r = await h.send({ type, user_gesture: true });
      assert.equal(r.error, "origin_mismatch", `${type} from ${senderOrigin}`);
      assert.equal(h.calls.length, 0);
    }
  }
  const ok = harness({ ok: true }, { senderOrigin: "https://example.test" });
  await ok.send({ type: "begin_browser", user_gesture: true });
  assert.equal(ok.calls.length, 1);
  const absent = harness({ ok: true });  // Safari / older Firefox: no sender.origin, the URL decides
  await absent.send({ type: "begin_browser", user_gesture: true });
  assert.equal(absent.calls.length, 1);
});
