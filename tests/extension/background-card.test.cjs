/* Service worker: card-fill allow-list, page-URL validation and context binding. No network. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const EXT = path.join(__dirname, "..", "..", "browser-extension");
const source = fs.readFileSync(path.join(EXT, "background.js"), "utf8");
const shim = fs.readFileSync(path.join(EXT, "api.js"), "utf8");

const TOP = "https://shop.example.test/checkout?step=pay";
function harness({ response = { ok: true }, active = true } = {}) {
  let listener; const calls = []; const id = "testextension";
  const frames = { 0: { documentId: "doc-top", url: TOP, documentLifecycle: "active", errorOccurred: false, parentFrameId: -1 } };
  const tab = { active, discarded: false };
  const chrome = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: {
      id, getManifest: () => ({ version: "0.3.3", permissions: ["favicon"] }), getURL: p => `chrome-extension://${id}/${p}`,
      onMessage: { addListener: f => listener = f },
      sendNativeMessage: (host, req) => { calls.push({ host, req }); return Promise.resolve({ ...response }); },
    },
    webNavigation: { getFrame: async ({ frameId }) => frames[frameId], onDOMContentLoaded: { addListener() {} }, onCompleted: { addListener() {} }, onHistoryStateUpdated: { addListener() {} } },
    tabs: { get: async () => tab, sendMessage: () => Promise.resolve() },
  };
  const context = vm.createContext({ chrome, URL, Set, Promise, setTimeout, clearTimeout, Uint8Array, btoa, fetch: async () => ({ ok: false }) });
  vm.runInContext(shim, context); vm.runInContext(source, context);
  const sender = { id, tab: { id: 8 }, frameId: 0, documentId: "doc-top", url: TOP };
  const send = (req = {}) => new Promise(resolve => listener({ origin: "https://shop.example.test", operation_id: "op-card", user_gesture: true, ...req }, sender, resolve));
  return { calls, send, tab };
}
const CONTEXT = [8, "doc-top", "https://shop.example.test", "op-card"];

test("card actions are allowed, pinned to card_protocol 1 and bound to the browser context", async () => {
  const h = harness({ response: { ok: true, card_protocol: 1, choices: [] } });
  for (const type of ["begin_card_browser", "approve_card_browser", "release_card_browser", "cancel_card_browser"]) {
    const r = await h.send({ type, card_protocol: 1, ...(type === "cancel_card_browser" ? { approval: "appr-1" } : {}) });
    assert.equal(r.ok, true, type);
  }
  assert.equal(h.calls.length, 4);
  for (const { req } of h.calls) {
    assert.equal(req.card_protocol, 1);
    assert.equal(req.protocol, 2);
    assert.deepEqual(JSON.parse(req.context), CONTEXT);
    assert.equal(req.tabId, undefined);
  }
  assert.equal(h.calls[0].req.user_gesture, true);
});

test("a card request without the card protocol pin is refused before native access", async () => {
  const h = harness();
  const r = await h.send({ type: "begin_card_browser" });
  assert.equal(r.error, "version_mismatch");
  const wrong = await h.send({ type: "begin_card_browser", card_protocol: 2 });
  assert.equal(wrong.error, "version_mismatch");
  assert.equal(h.calls.length, 0);
});

test("approve_card_browser forwards only typed cc-* tokens, revision, approval and session", async () => {
  const h = harness({ response: { ok: true, approval: "appr-1" } });
  const r = await h.send({ type: "approve_card_browser", card_protocol: 1, entry_id: "card-1", revision: 4, fields: ["cc-name", "cc-number", "cc-exp"], session_id: "s1" });
  assert.equal(r.ok, true);
  const req = h.calls[0].req;
  assert.equal(req.action, "approve_card_browser");
  assert.deepEqual([...req.fields], ["cc-name", "cc-number", "cc-exp"]);
  assert.equal(req.entry_id, "card-1"); assert.equal(req.revision, 4); assert.equal(req.session_id, "s1");
  const rel = await h.send({ type: "release_card_browser", card_protocol: 1, entry_id: "card-1", revision: 4, fields: ["cc-number"], approval: "appr-1", gesture_nonce: "ab".repeat(16) });
  assert.equal(rel.ok, true);
  assert.equal(h.calls[1].req.approval, "appr-1");
  assert.equal(h.calls[1].req.gesture_nonce, "ab".repeat(16), "nonce forwarded verbatim as for get_browser");
});

test("card field lists are validated: non-card tokens, duplicates, empty and oversized lists are refused", async () => {
  const h = harness();
  const bad = [["password"], ["cc-number", "cc-number"], [], ["cc-pin"], ["email"], "cc-number", [1], Array(8).fill("cc-name")];
  for (const fields of bad) {
    const r = await h.send({ type: "approve_card_browser", card_protocol: 1, entry_id: "card-1", revision: 1, fields });
    assert.equal(r.error, "invalid_card_fields", JSON.stringify(fields));
  }
  assert.equal((await h.send({ type: "approve_card_browser", card_protocol: 1, entry_id: "card-1", revision: 0, fields: ["cc-number"] })).error, "invalid_request");
  assert.equal((await h.send({ type: "release_card_browser", card_protocol: 1, entry_id: "card-1", revision: 1, fields: ["cc-number"], approval: "x".repeat(129) })).error, "invalid_approval");
  assert.equal(h.calls.length, 0);
});

test("card actions need the active tab", async () => {
  const h = harness({ active: false });
  for (const type of ["begin_card_browser", "approve_card_browser", "release_card_browser", "cancel_card_browser"]) {
    const r = await h.send({ type, card_protocol: 1 });
    assert.equal(r.error, "destination_changed", type);
  }
  assert.equal(h.calls.length, 0);
});

test("a same-origin page url is forwarded with begin_browser and get_browser, with its fragment stripped", async () => {
  const h = harness();
  await h.send({ type: "begin_browser", url: "https://shop.example.test/checkout?step=pay#card" });
  assert.equal(h.calls[0].req.url, "https://shop.example.test/checkout?step=pay");
  await h.send({ type: "get_browser", grant: "g", entry_id: "e1", url: "https://shop.example.test/checkout" });
  assert.equal(h.calls[1].req.url, "https://shop.example.test/checkout");
});

test("a url that does not belong to the sender origin, carries credentials, or is malformed is dropped, not forwarded", async () => {
  const h = harness();
  const dropped = [
    "https://other.test/checkout",                 // different host
    "https://shop.example.test:8443/checkout",     // different port
    "http://shop.example.test/checkout",           // different scheme
    "https://user:pw@shop.example.test/checkout",  // credentials
    "https://shop.example.test.evil.test/x",       // lookalike
    "not a url", "", 42, {}, ["https://shop.example.test/"],
    "https://shop.example.test/" + "a".repeat(5000),
  ];
  for (const url of dropped) {
    const r = await h.send({ type: "begin_browser", url });
    assert.equal(r.ok, true, String(url));
    assert.equal("url" in h.calls.at(-1).req, false, `forwarded: ${String(url)}`);
  }
  assert.equal(h.calls.length, dropped.length, "the request itself still goes through on origin alone");
});

test("the url is only attached to begin_browser and get_browser, never to other actions", async () => {
  const h = harness();
  await h.send({ type: "save_browser", username: "a", password: "b", url: "https://shop.example.test/checkout" });
  await h.send({ type: "begin_card_browser", card_protocol: 1, url: "https://shop.example.test/checkout" });
  await h.send({ type: "begin_totp_browser", url: "https://shop.example.test/checkout" });
  for (const { req } of h.calls) assert.equal("url" in req, false, req.action);
});

test("card errors from the broker get readable messages", async () => {
  for (const [error, pattern] of [["card_not_found", /No payment card/], ["invalid_card_fields", /reviewed card fields/], ["user_cancelled", /cancelled/]]) {
    const h = harness({ response: { ok: false, error } });
    const r = await h.send({ type: "begin_card_browser", card_protocol: 1 });
    assert.equal(r.error, error);
    assert.match(r.message, pattern);
  }
});
