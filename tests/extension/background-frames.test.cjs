/* Service-worker frame-tree and cross-browser checks against deterministic mocks. No network. */
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
function harness({ frames, firefox = false, permissions = ["favicon"], response = { ok: true } } = {}) {
  let listener; const calls = [], nudges = [], fetches = [], navListeners = {}; const id = "testextension";
  frames = frames || { 0: { documentId: "doc-top", url: TOP, documentLifecycle: "active", errorOccurred: false, parentFrameId: -1 } };
  const tab = { active: true, discarded: false };
  const ns = {
    runtime: {
      id, getManifest: () => ({ version: "0.3.0", permissions }), getURL: p => `chrome-extension://${id}/${p}`,
      onMessage: { addListener: f => listener = f },
      sendNativeMessage: (host, req) => { calls.push({ host, req }); return Promise.resolve({ ...response }); },
      sendMessage: () => Promise.resolve(),
    },
    webNavigation: {
      getFrame: async ({ tabId, frameId }) => { assert.equal(tabId, 8); return frames[frameId]; },
      onDOMContentLoaded: { addListener: f => navListeners.dom = f }, onCompleted: { addListener: f => navListeners.completed = f }, onHistoryStateUpdated: { addListener: f => navListeners.history = f },
    },
    tabs: { get: async () => tab, sendMessage: (tabId, message, options) => { nudges.push({ tabId, message, options }); return Promise.resolve(); } },
  };
  const globals = { URL, Set, Promise, setTimeout, clearTimeout, Uint8Array, btoa, fetch: async url => { fetches.push(String(url)); return { ok: false }; } };
  if (firefox) globals.browser = ns; else globals.chrome = ns;
  const context = vm.createContext(globals);
  vm.runInContext(shim, context); vm.runInContext(source, context);
  const sender = (frameId, url, documentId) => ({ id, tab: { id: 8 }, frameId, url, ...(documentId === undefined ? {} : { documentId }) });
  const send = (who, req = {}) => new Promise(resolve => listener({ type: "begin_browser", origin: new URL(who.url).origin, operation_id: "op1", user_gesture: true, ...req }, who, resolve));
  return { calls, nudges, fetches, navListeners, frames, tab, sender, send, context };
}

const top = { documentId: "doc-top", url: TOP, documentLifecycle: "active", errorOccurred: false, parentFrameId: -1 };
const child = (url, parentFrameId, documentId) => ({ documentId, url, documentLifecycle: "active", errorOccurred: false, parentFrameId });

test("a same-origin child frame is accepted and its own document pins the context", async () => {
  const h = harness({ frames: { 0: top, 3: child("https://example.test/embed/login", 0, "doc-child") } });
  const r = await h.send(h.sender(3, "https://example.test/embed/login", "doc-child"));
  assert.equal(r.ok, true);
  assert.equal(h.calls.length, 1);
  assert.deepEqual(JSON.parse(h.calls[0].req.context), [8, "doc-child", "https://example.test", "op1"]);
});

test("a cross-origin child frame is rejected even though its own origin is self-consistent", async () => {
  const h = harness({ frames: { 0: top, 3: child("https://other.test/widget", 0, "doc-child") } });
  const r = await h.send(h.sender(3, "https://other.test/widget", "doc-child"));
  assert.equal(r.ok, false);
  assert.equal(r.error, "destination_changed");
  assert.equal(h.calls.length, 0);
});

test("a same-origin frame nested under a cross-origin ancestor is rejected", async () => {
  const h = harness({ frames: { 0: top, 2: child("https://other.test/wrap", 0, "doc-b"), 5: child("https://example.test/inner", 2, "doc-a2") } });
  const r = await h.send(h.sender(5, "https://example.test/inner", "doc-a2"));
  assert.equal(r.ok, false);
  assert.equal(h.calls.length, 0);
});

test("unknown frames, frames in error, and forged frame ids are rejected", async () => {
  const h = harness({ frames: { 0: top, 4: { ...child("https://example.test/x", 0, "doc-x"), errorOccurred: true } } });
  assert.equal((await h.send(h.sender(9, TOP, "doc-top"))).ok, false, "frame id the browser does not know");
  assert.equal((await h.send(h.sender(4, "https://example.test/x", "doc-x"))).ok, false, "errorOccurred");
  assert.equal((await h.send(h.sender(-1, TOP, "doc-top"))).ok, false, "negative frame id");
  assert.equal((await h.send(h.sender("0", TOP, "doc-top"))).ok, false, "non-integer frame id");
  assert.equal(h.calls.length, 0);
});

test("a child frame whose documentId no longer matches is rejected", async () => {
  const h = harness({ frames: { 0: top, 3: child("https://example.test/embed", 0, "doc-new") } });
  assert.equal((await h.send(h.sender(3, "https://example.test/embed", "doc-old"))).ok, false);
  assert.equal(h.calls.length, 0);
});

test("navigation nudges are delivered to the navigated frame, never to chrome:// frames", async () => {
  const h = harness();
  h.navListeners.dom({ tabId: 8, frameId: 3, url: "https://example.test/embed" });
  h.navListeners.history({ tabId: 8, frameId: 0, url: "https://example.test/app" });
  h.navListeners.completed({ tabId: 8, frameId: 0, url: "chrome://newtab" });
  h.navListeners.completed({ tabId: 8, frameId: -1, url: TOP });
  assert.deepEqual(h.nudges.map(n => n.options.frameId), [3, 0]);
  assert.ok(h.nudges.every(n => n.message.command === "check_pending_save" && n.tabId === 8));
});

test("Firefox: browser.* namespace, no documentId, no _favicon; falls back to tab + frame origin and a neutral icon", async () => {
  const ffTop = { url: TOP, errorOccurred: false, parentFrameId: -1 }; // no documentId / documentLifecycle
  const h = harness({ firefox: true, permissions: ["nativeMessaging", "scripting", "storage", "webNavigation", "activeTab"], frames: { 0: ffTop, 3: { url: "https://example.test/embed", errorOccurred: false, parentFrameId: 0 } } });
  const r = await h.send(h.sender(0, TOP), { type: "save_browser", username: "alice", password: "pw" });
  assert.equal(r.ok, true);
  assert.deepEqual(JSON.parse(h.calls[0].req.context), [8, "frame:0", "https://example.test", "op1"]);
  assert.equal(h.calls[0].req.site_icon, undefined, "no favicon payload without the Chromium endpoint");
  assert.equal(h.fetches.length, 0, "the _favicon endpoint is never fetched");
  const c = await h.send(h.sender(3, "https://example.test/embed"));
  assert.equal(c.ok, true, "same-origin child frame accepted on Firefox too");
  assert.deepEqual(JSON.parse(h.calls[1].req.context), [8, "frame:3", "https://example.test", "op1"]);
  const x = await h.send(h.sender(3, "https://other.test/embed"));
  assert.equal(x.ok, false, "cross-origin child frame still rejected on Firefox");
});

test("Firefox fallback is origin-bound: a frame now on another origin is rejected", async () => {
  const h = harness({ firefox: true, permissions: [], frames: { 0: { url: "https://other.test/landing", errorOccurred: false, parentFrameId: -1 } } });
  assert.equal((await h.send(h.sender(0, TOP))).ok, false);
  assert.equal(h.calls.length, 0);
});

test("a documentId present on one side only is a mismatch", async () => {
  const h = harness({ frames: { 0: { url: TOP, errorOccurred: false, parentFrameId: -1 } } });
  assert.equal((await h.send(h.sender(0, TOP, "doc-top"))).ok, false, "sender has documentId, frame does not");
  const g = harness();
  assert.equal((await g.send(g.sender(0, TOP))).ok, false, "frame has documentId, sender does not");
});

test("Chromium: a save request on an unknown page fetches the favicon once and tolerates a failed fetch", async () => {
  const h = harness();
  const r = await h.send(h.sender(0, TOP, "doc-top"), { type: "save_browser", username: "alice", password: "pw" });
  assert.equal(r.ok, true);
  assert.equal(h.fetches.length, 1);
  assert.match(h.fetches[0], /\/_favicon\/\?pageUrl=/);
  assert.equal(h.calls[0].req.site_icon, undefined);
});
