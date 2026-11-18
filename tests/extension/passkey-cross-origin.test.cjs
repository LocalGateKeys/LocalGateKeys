/* Passkey sign-in inside another site's frame (known limitation 4): the service worker derives the top
 * origin from the browser's frame tree, binds it into the context and forwards a get only when the bridge
 * read the frame's publickey-credentials-get permission as allowed. Create, same-origin frames and
 * top-level pages are unchanged. No network. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const EXT = path.join(__dirname, "..", "..", "browser-extension");
const source = fs.readFileSync(path.join(EXT, "background.js"), "utf8");
const shim = fs.readFileSync(path.join(EXT, "api.js"), "utf8");
const bridgeSource = fs.readFileSync(path.join(EXT, "webauthn-bridge.js"), "utf8");
const plain = value => JSON.parse(JSON.stringify(value));
const flush = () => new Promise(resolve => setImmediate(resolve));

const SHOP = "https://shop.example";
const PAY = "https://pay.example.test";
const frame = (url, parentFrameId, documentId) => ({ documentId, url, documentLifecycle: "active", errorOccurred: false, parentFrameId });
const shopTop = () => frame(`${SHOP}/checkout`, -1, "doc-top");

function harness({ frames, tabUrl = `${SHOP}/checkout`, response } = {}) {
  let listener; const calls = []; const id = "testextension";
  frames = frames || { 0: shopTop(), 3: frame(`${PAY}/widget`, 0, "doc-pay") };
  const tab = { active: true, discarded: false, url: tabUrl };
  const chrome = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: {
      id, getManifest: () => ({ version: "0.4.12", permissions: [] }), getURL: p => `chrome-extension://${id}/${p}`,
      onMessage: { addListener: f => listener = f },
      sendNativeMessage: (host, req) => {
        calls.push(plain(req));
        const r = typeof response === "function" ? response(req, frames, tab) : response;
        return Promise.resolve({ ...(r || { ok: true, passkey_protocol: 1, credential: { credential_id: "x" } }) });
      },
    },
    webNavigation: { getFrame: async ({ tabId, frameId }) => { assert.equal(tabId, 8); return frames[frameId]; },
      onDOMContentLoaded: { addListener() {} }, onCompleted: { addListener() {} }, onHistoryStateUpdated: { addListener() {} } },
    tabs: { get: async () => tab, sendMessage: () => Promise.resolve() },
  };
  const context = vm.createContext({ chrome, URL, Set, Promise, setTimeout, clearTimeout, Uint8Array, btoa, fetch: async () => ({ ok: false }) });
  vm.runInContext(shim, context); vm.runInContext(source, context);
  const sender = (frameId, url, documentId) => ({ id, tab: { id: 8, url: tabUrl }, frameId, url, documentId, origin: new URL(url).origin });
  const send = (who, req = {}) => new Promise(resolve => listener({ type: "passkey_get_browser", origin: new URL(who.url).origin,
    operation_id: "pk-r1", passkey_protocol: 1, options: { challenge: "abc" }, publickey_get_policy: "allowed", ...req }, who, resolve));
  return { calls, send, sender, frames, tab };
}
const payFrame = h => h.sender(3, `${PAY}/widget`, "doc-pay");

test("a get from a cross-origin frame carries the browser's top origin, bound into the context", async () => {
  const h = harness();
  const r = await h.send(payFrame(h));
  assert.equal(r.ok, true);
  assert.equal(h.calls.length, 1);
  const req = h.calls[0];
  assert.equal(req.action, "passkey_get_browser");
  assert.equal(req.origin, PAY, "the frame's own origin (the rpId is checked against it)");
  assert.equal(req.top_origin, SHOP);
  assert.equal(req.publickey_get_allowed, true);
  assert.deepEqual(JSON.parse(req.context), [8, "doc-pay", PAY, "pk-r1", SHOP]);
});

test("a top origin or permission the message claims is ignored: only the browser's frame tree counts", async () => {
  const h = harness();
  await h.send(payFrame(h), { top_origin: "https://evil.test", topOrigin: "https://evil.test", publickey_get_allowed: true,
    context: "[1,\"x\",\"https://evil.test\",\"y\",\"https://evil.test\"]" });
  assert.equal(h.calls[0].top_origin, SHOP);
  assert.deepEqual(JSON.parse(h.calls[0].context), [8, "doc-pay", PAY, "pk-r1", SHOP]);
  // A top-level page that claims to be framed is still top-level.
  const top = harness({ frames: { 0: shopTop() } });
  await top.send(top.sender(0, `${SHOP}/checkout`, "doc-top"), { top_origin: "https://evil.test", publickey_get_allowed: true });
  const req = top.calls[0];
  assert.equal(req.top_origin, undefined);
  assert.equal(req.publickey_get_allowed, undefined);
  assert.deepEqual(JSON.parse(req.context), [8, "doc-top", SHOP, "pk-r1"]);
});

test("without the frame's publickey-credentials-get permission the browser answers", async () => {
  for (const policy of ["denied", undefined, "unknown", true, "ALLOWED"]) {
    const h = harness();
    const r = await h.send(payFrame(h), { publickey_get_policy: policy });
    assert.deepEqual(plain(r), { ok: false, error: "fallback" }, String(policy));
    assert.equal(h.calls.length, 0);
  }
});

test("a top origin the browser cannot establish with certainty means fallback", async () => {
  const cases = [
    { frames: { 0: frame("about:blank", -1, "doc-top"), 3: frame(`${PAY}/widget`, 0, "doc-pay") } },
    { frames: { 0: frame("data:text/html,x", -1, "doc-top"), 3: frame(`${PAY}/widget`, 0, "doc-pay") } },
    { tabUrl: "https://elsewhere.example/" },   // the tab disagrees with the top frame
    { tabUrl: null },                           // the tab's URL is not readable
    { frames: { 0: shopTop(), 2: frame("about:srcdoc", 0, "doc-mid"), 3: frame(`${PAY}/widget`, 2, "doc-pay") } },
  ];
  for (const options of cases) {
    const h = harness(options);
    const r = await h.send(payFrame(h));
    assert.equal(r.ok, false, JSON.stringify(options));
    assert.equal(r.error, "fallback", JSON.stringify(options));
    assert.equal(h.calls.length, 0);
  }
});

test("a create in a cross-origin frame never reaches the app (unchanged: the browser handles it)", async () => {
  const h = harness();
  const r = await h.send(payFrame(h), { type: "passkey_create_browser", user_activation: true });
  assert.equal(r.ok, false);
  assert.equal(r.error, "destination_changed");
  assert.equal(h.calls.length, 0);
  // Confirm and discard never carry a top origin either.
  await h.send(payFrame(h), { type: "passkey_confirm_browser" });
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].top_origin, undefined);
  assert.equal(JSON.parse(h.calls[0].context).length, 4);
});

test("other actions from a cross-origin frame are still refused", async () => {
  const h = harness();
  const r = await h.send(payFrame(h), { type: "begin_browser", user_gesture: true });
  assert.equal(r.error, "destination_changed");
  assert.equal(h.calls.length, 0);
});

test("nested frames: any ancestor of another origin makes it cross-origin; topOrigin is the top document's", async () => {
  const nested = harness({ frames: { 0: shopTop(), 2: frame("https://widgets.other.test/w", 0, "doc-mid"), 5: frame(`${PAY}/inner`, 2, "doc-pay") } });
  await nested.send(nested.sender(5, `${PAY}/inner`, "doc-pay"));
  assert.equal(nested.calls[0].top_origin, SHOP);
  assert.deepEqual(JSON.parse(nested.calls[0].context), [8, "doc-pay", PAY, "pk-r1", SHOP]);
  // Same origin as the top, but under a frame of another site: still cross-origin (A > B > A).
  const aba = harness({ frames: { 0: shopTop(), 2: frame("https://widgets.other.test/w", 0, "doc-mid"), 5: frame(`${SHOP}/inner`, 2, "doc-a2") } });
  await aba.send(aba.sender(5, `${SHOP}/inner`, "doc-a2"));
  assert.equal(aba.calls[0].top_origin, SHOP);
  assert.equal(JSON.parse(aba.calls[0].context).length, 5);
});

test("the same frame document under two top sites gets two contexts", async () => {
  const a = harness();
  await a.send(payFrame(a));
  const b = harness({ frames: { 0: frame("https://news.example/story", -1, "doc-top"), 3: frame(`${PAY}/widget`, 0, "doc-pay") },
    tabUrl: "https://news.example/story" });
  await b.send(payFrame(b));
  assert.notEqual(a.calls[0].context, b.calls[0].context);
  assert.equal(b.calls[0].top_origin, "https://news.example");
});

test("same-origin frames and top-level pages keep today's payload and context bytes", async () => {
  const h = harness({ frames: { 0: shopTop(), 3: frame(`${SHOP}/embed`, 0, "doc-child") } });
  await h.send(h.sender(3, `${SHOP}/embed`, "doc-child"), { publickey_get_policy: "denied" });
  await h.send(h.sender(0, `${SHOP}/checkout`, "doc-top"), { publickey_get_policy: undefined });
  assert.equal(h.calls.length, 2, "the policy is only consulted for cross-origin frames");
  assert.equal(h.calls[0].context, JSON.stringify([8, "doc-child", SHOP, "pk-r1"]));
  assert.equal(h.calls[1].context, JSON.stringify([8, "doc-top", SHOP, "pk-r1"]));
  for (const req of h.calls) {
    assert.deepEqual(Object.keys(req).sort(), ["action", "context", "extension_version", "options", "origin", "passkey_protocol",
      "protocol", "user_activation", "user_gesture", "username_only"]);
  }
});

test("a reply is dropped when the top site changed while the dialog was open", async () => {
  const h = harness({ response: (req, frames, tab) => {
    frames[0] = frame("https://evil.example/", -1, "doc-top"); tab.url = "https://evil.example/";
    return { ok: true, passkey_protocol: 1, credential: { credential_id: "x" } };
  } });
  const r = await h.send(payFrame(h));
  assert.equal(r.error, "destination_changed");
});

// ---- The bridge reads the permission in the isolated world; a page cannot reach that reading.
function bridge({ document } = {}) {
  const window = new EventTarget();
  window.location = { origin: PAY };
  const sent = [];
  const chrome = { runtime: { sendMessage: msg => { sent.push(plain(msg)); return Promise.resolve({ ok: false, error: "fallback" }); } } };
  const isolated = vm.createContext({ window, self: { origin: PAY }, location: window.location, chrome, Promise, Map, Object, JSON, String,
    CustomEvent, Uint8Array, crypto: globalThis.crypto, navigator: {}, ...(document ? { document } : {}) });
  isolated.globalThis = isolated;
  vm.runInContext(shim, isolated);
  vm.runInContext(bridgeSource, isolated);
  const secret = "0123456789abcdef0123456789abcdef";
  window.dispatchEvent(new CustomEvent("lgk-passkey-hello", { detail: secret }));
  const ask = kind => window.dispatchEvent(new CustomEvent(`lgk-passkey-req-${secret}`,
    { detail: JSON.stringify({ id: `r-${kind}`, kind, options: {} }) }));
  return { sent, ask };
}
const policyDocument = (allowed, api = "featurePolicy") => ({ [api]: { allowsFeature: feature => feature === "publickey-credentials-get" && allowed } });

test("the bridge reports the frame's publickey-credentials-get permission for a get only", async () => {
  for (const [document, expected] of [
    [policyDocument(true), "allowed"], [policyDocument(false), "denied"],
    [policyDocument(true, "permissionsPolicy"), "allowed"], [policyDocument(false, "permissionsPolicy"), "denied"],
    [{}, undefined], [undefined, undefined],    // Firefox: no policy API, so cross-origin frames fall back
    [{ featurePolicy: { allowsFeature() { throw new Error("x"); } } }, undefined],
  ]) {
    const b = bridge({ document });
    b.ask("get"); b.ask("create");
    await flush();
    const [get, create] = b.sent;
    assert.equal(get.publickey_get_policy, expected, JSON.stringify(document));
    assert.equal("publickey_get_policy" in create, false);
  }
});
