/* Service worker: the native host's item_limit refusal reaches the page with the upgrade text. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const EXT = path.join(__dirname, "..", "..", "browser-extension");
const source = fs.readFileSync(path.join(EXT, "background.js"), "utf8");
const shim = fs.readFileSync(path.join(EXT, "api.js"), "utf8");
const TOP = "https://example.test/login";
const ITEM_LIMIT_TEXT = "Your free LocalGateKeys holds 4 items. Upgrade to Pro for unlimited.";

function harness(response) {
  let listener; const calls = []; const id = "testextension";
  const frames = { 0: { documentId: "doc-top", url: TOP, documentLifecycle: "active", errorOccurred: false, parentFrameId: -1 } };
  const chrome = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: {
      id, getManifest: () => ({ version: "0.3.3", permissions: ["favicon"] }), getURL: p => `chrome-extension://${id}/${p}`,
      onMessage: { addListener: f => listener = f },
      sendNativeMessage: (host, req) => { calls.push(req); return Promise.resolve({ ...response }); },
    },
    webNavigation: { getFrame: async ({ frameId }) => frames[frameId], onDOMContentLoaded: { addListener() {} }, onCompleted: { addListener() {} }, onHistoryStateUpdated: { addListener() {} } },
    tabs: { get: async () => ({ active: true, discarded: false }), sendMessage: () => Promise.resolve() },
  };
  const context = vm.createContext({ chrome, URL, Set, Promise, setTimeout, clearTimeout, Uint8Array, btoa, fetch: async () => ({ ok: false }) });
  vm.runInContext(shim, context); vm.runInContext(source, context);
  const sender = { id, tab: { id: 8 }, frameId: 0, documentId: "doc-top", url: TOP };
  const send = req => new Promise(resolve => listener({ origin: "https://example.test", operation_id: "op-1", user_gesture: true, ...req }, sender, resolve));
  return { calls, send };
}

for (const type of ["save_browser", "save_pending_browser"]) {
  test(`${type}: an item_limit refusal carries the upgrade message and the limit`, async () => {
    const h = harness({ ok: false, error: "item_limit", limit: 4 });
    const payload = type === "save_browser" ? { username: "alice", password: "pw" } : { pending_token: "tok-1" };
    const r = await h.send({ type, gesture_nonce: "ab".repeat(16), ...payload });
    assert.equal(h.calls.length, 1, "the request reached the native host");
    assert.equal(r.ok, false);
    assert.equal(r.error, "item_limit");
    assert.equal(r.limit, 4);
    assert.equal(r.message, ITEM_LIMIT_TEXT);
  });
}

test("the item_limit message uses the limit the host reports", async () => {
  const h = harness({ ok: false, error: "item_limit", limit: 7 });
  const r = await h.send({ type: "save_browser", gesture_nonce: "ab".repeat(16), username: "alice", password: "pw" });
  assert.equal(r.message, "Your free LocalGateKeys holds 7 items. Upgrade to Pro for unlimited.");
});
