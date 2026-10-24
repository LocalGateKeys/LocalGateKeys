/* Extended audit 2026-10-24, stream C: extension-side fixes.
 * M-3 / L-18 Safari probe limit, document binding, frame chain; content.js
 * Escape and panel host; L-15 handoff without username; L-12 hint text cap;
 * L-17 passkey create needs a user activation; I-14 Firefox per-document key;
 * I-20 no build scripts in the Firefox build. No network. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const nodeCrypto = require("node:crypto");
const { createPage } = require("./helpers.cjs");

const EXT = path.join(__dirname, "..", "..", "browser-extension");
const read = name => fs.readFileSync(path.join(EXT, name), "utf8");
const plain = value => JSON.parse(JSON.stringify(value));
const ORIGIN = "https://example.test", PAGE = "https://example.test/login";
const KEY_A = "a".repeat(32), KEY_B = "b".repeat(32);

// ---- background-safari.js -----------------------------------------------------

function safari({ native = () => ({ status: "new" }), frames = null } = {}) {
  const id = "safariext", clock = { now: 1_700_000_000_000 }, calls = [], listeners = {};
  class FakeDate extends Date { static now() { return clock.now; } }
  const ns = {
    runtime: {
      id, getManifest: () => ({ version: "0.4.5" }), sendMessage: () => Promise.resolve(),
      onMessage: { addListener: f => { listeners.message = f; } },
      sendNativeMessage: (app, message) => { calls.push({ ...message }); return Promise.resolve(native(message)); },
    },
    tabs: { onUpdated: { addListener() {} }, onRemoved: { addListener() {} }, sendMessage: () => Promise.resolve() },
  };
  if (frames) ns.webNavigation = { getFrame: async ({ frameId }) => frames[frameId] };
  const context = vm.createContext({ URL, Map, Set, Promise, setTimeout, clearTimeout, Uint8Array, Date: FakeDate,
    crypto: { getRandomValues: a => nodeCrypto.getRandomValues(a) }, browser: ns });
  vm.runInContext(read("api.js"), context);
  vm.runInContext(read("background-safari.js"), context);
  const sender = (url = PAGE, extra = {}) => ({ id, tab: { id: 8, url: extra.top || url }, frameId: 0, url, ...extra });
  let op = 0;
  const send = (request, who = sender()) => new Promise(resolve => {
    listeners.message({ origin: new URL(who.url).origin, operation_id: `op-${++op}`, ...request }, who, r => resolve(plain(r)));
  });
  return { calls, clock, sender, send };
}

test("Safari: capture/check are limited to 10 per origin per minute, without reaching the app", async () => {
  const h = safari();
  for (let i = 0; i < 10; i++) {
    const type = i % 2 ? "check_browser" : "capture_browser";
    assert.equal((await h.send({ type, username: "alice", password: `guess-${i}` })).ok, true, `probe ${i}`);
  }
  const before = h.calls.length;
  const blocked = await h.send({ type: "capture_browser", username: "alice", password: "guess-x" });
  assert.equal(blocked.ok, false);
  assert.equal(blocked.error, "rate_limited");
  assert.equal(h.calls.length, before, "the 11th guess never reaches the native handler");
  const other = await h.send({ type: "capture_browser", origin: "https://other.test", username: "bob", password: "x" }, h.sender("https://other.test/"));
  assert.equal(other.ok, true, "another origin has its own budget");
  h.clock.now += 60_000;
  assert.equal((await h.send({ type: "check_browser", username: "alice", password: "later" })).ok, true, "the window slides");
});

test("Safari: the overall budget is a backstop; each origin keeps a small share", async () => {
  const h = safari();
  for (let i = 0; i < 30; i++) {
    const origin = `https://s${i % 3}.flood.test`;
    await h.send({ type: "check_browser", origin, username: "u", password: `p${i}` }, h.sender(`${origin}/`));
  }
  const fresh = "https://fresh.test";
  for (let i = 0; i < 3; i++) assert.equal((await h.send({ type: "check_browser", origin: fresh, username: "u", password: "p" }, h.sender(`${fresh}/`))).ok, true);
  assert.equal((await h.send({ type: "check_browser", origin: fresh, username: "u", password: "p" }, h.sender(`${fresh}/`))).error, "rate_limited");
});

test("Safari: a same-site handoff names the origin but never the username", async () => {
  const LOGIN = "https://login.paddle.com", LANDING = "https://vendors.paddle.com";
  const h = safari({ native: m => m.action === "same_site" ? { same: true } : { status: "new" } });
  await h.send({ type: "capture_browser", origin: LOGIN, username: "ada@example.test", password: "pw", document_key: KEY_A }, h.sender(`${LOGIN}/`));
  const there = await h.send({ type: "pending_browser", origin: LANDING, document_key: KEY_B }, h.sender(`${LANDING}/`));
  assert.equal(there.pending, true);
  assert.equal(there.origin, LOGIN);
  assert.equal(there.handoff, true);
  assert.equal(there.username, undefined);
  assert.doesNotMatch(JSON.stringify(there), /ada/);
});

test("Safari: a capture is bound to its document; another document gets it only during the redirect grace", async () => {
  const h = safari();
  await h.send({ type: "capture_browser", username: "alice", password: "pw", document_key: KEY_A });
  const same = await h.send({ type: "pending_browser", document_key: KEY_A });
  assert.equal(same.pending, true);
  assert.equal(same.username, "alice");
  h.clock.now += 12_000;
  assert.equal((await h.send({ type: "pending_browser", document_key: KEY_B })).pending, false, "a later document gets nothing");
  assert.equal((await h.send({ type: "pending_browser", document_key: KEY_A })).pending, false, "and the capture is dropped");

  const g = safari();
  await g.send({ type: "capture_browser", username: "alice", password: "pw", document_key: KEY_A });
  g.clock.now += 2_000;
  assert.equal((await g.send({ type: "pending_browser", document_key: KEY_B })).pending, true, "the landing document of a form post");
  assert.equal((await g.send({ type: "pending_browser", document_key: KEY_A })).pending, true, "still within the grace");
  g.clock.now += 11_000;
  assert.equal((await g.send({ type: "pending_browser", document_key: KEY_B })).pending, false, "now bound to the first document that took it");
});

test("Safari: a gesture nonce minted in one document does not work in another", async () => {
  const h = safari({ native: m => (m.action === "classify" ? { status: "new" } : { stored: true }) });
  const minted = await h.send({ type: "begin_gesture_browser", user_gesture: true, operation_id: "op-g", document_key: KEY_A });
  const r = await h.send({ type: "save_browser", username: "a", password: "b", user_gesture: true, gesture_nonce: minted.gesture_nonce, operation_id: "op-g", document_key: KEY_B });
  assert.equal(r.error, "gesture_nonce_invalid");
});

test("Safari: pending captures expire after 90 s", async () => {
  const h = safari();
  await h.send({ type: "capture_browser", username: "alice", password: "pw" });
  h.clock.now += 90_000;
  assert.equal((await h.send({ type: "pending_browser" })).pending, false);
});

test("Safari: with webNavigation every frame up to the top is checked", async () => {
  const frames = {
    0: { url: "https://example.test/", parentFrameId: -1, errorOccurred: false },
    4: { url: "https://evil.test/wrap", parentFrameId: 0, errorOccurred: false },
    7: { url: "https://example.test/embed", parentFrameId: 4, errorOccurred: false },
    9: { url: "https://example.test/embed", parentFrameId: 0, errorOccurred: false },
  };
  const h = safari({ frames });
  const nested = h.sender("https://example.test/embed", { frameId: 7, top: "https://example.test/" });
  assert.equal((await h.send({ type: "capture_browser", username: "a", password: "b" }, nested)).error, "origin_mismatch", "a cross-origin middle frame");
  const direct = h.sender("https://example.test/embed", { frameId: 9, top: "https://example.test/" });
  assert.equal((await h.send({ type: "capture_browser", username: "a", password: "b" }, direct)).ok, true);
  assert.equal(h.calls.filter(c => c.action === "classify").length, 1);
});

// ---- content.js -------------------------------------------------------------

const LOGIN_FORM = `<form id="login" action="/session" method="post">
  <input id="user" type="text" name="username" autocomplete="username">
  <input id="pw" type="password" name="password">
  <button id="submit" type="submit">Sign in</button>
</form>`;
function responder(state, pendingReply) {
  return async request => {
    switch (request.type) {
      case "capture_browser": state.captures = (state.captures || 0) + 1; return { ok: true, stored: true, pending_token: "tok-1" };
      case "pending_browser": return pendingReply();
      case "clear_pending_browser": state.cleared = (state.cleared || 0) + 1; return { ok: true };
      default: return { ok: true };
    }
  };
}
async function pageWithPrompt(pendingReply = () => ({ ok: true, pending: true, pending_token: "tok-1", username: "alice", status: "new", age_ms: 0 })) {
  const state = {};
  const p = createPage({ html: LOGIN_FORM, respond: responder(state, pendingReply) });
  p.load();
  await p.tick();
  p.document.getElementById("login").remove();
  p.clock.now += 1000;
  await p.command("check_pending_save");
  await p.sleep(140);
  await p.tick(4);
  return { p, state };
}

test("content: a page-dispatched Escape does not close the save panel; the user's own Escape does", async () => {
  const { p } = await pageWithPrompt();
  assert.equal(p.panelVisible(), true);
  p.document.dispatchEvent(new p.window.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  assert.equal(p.panelVisible(), true, "untrusted Escape ignored");
  p.trusted(p.document.body, "keydown", { key: "Escape" }, p.impls.KeyboardEventImpl);
  assert.equal(p.panelVisible(), false);
});

test("content: a hidden panel is detached, not left in the page with display:none", async () => {
  const { p } = await pageWithPrompt();
  const host = p.panelHost();
  assert.ok(host && host.isConnected);
  assert.equal(p.shadows.get(host).mode, "closed");
  p.trusted(p.document.body, "keydown", { key: "Escape" }, p.impls.KeyboardEventImpl);
  assert.equal(host.isConnected, false);
  assert.equal(p.document.querySelector("[data-localgatekeys-panel]"), null, "nothing left for the page to poll");
});

test("content: a same-site handoff prompt shows the origin, not a username, and is not discarded", async () => {
  const { p, state } = await pageWithPrompt(() => ({ ok: true, pending: true, pending_token: "tok-1", status: "new", age_ms: 0,
    origin: "https://login.example.test", handoff: true }));
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /A login typed on https:\/\/login\.example\.test/);
  assert.equal(state.cleared || 0, 0);
});

test("content: every message carries one per-document key", async () => {
  const p = createPage({ html: LOGIN_FORM, respond: async () => ({ ok: true }) });
  p.load();
  await p.tick();
  p.document.getElementById("user").value = "alice";
  p.document.getElementById("pw").value = "pw";
  p.trusted(p.document.getElementById("login"), "submit", {}, p.impls.SubmitEventImpl);
  await p.tick(4);
  const keys = new Set(p.messages.map(m => m.document_key));
  assert.ok(p.messages.length >= 1);
  assert.equal(keys.size, 1);
  assert.match([...keys][0], /^[0-9a-f]{32}$/);
});

test("content: a submit on a page the user never interacted with is not captured", async () => {
  const state = {};
  const p = createPage({ html: LOGIN_FORM, respond: responder(state, () => ({ ok: true, pending: false })) });
  Object.defineProperty(p.window.navigator, "userActivation", { value: { hasBeenActive: false, isActive: false }, configurable: true });
  p.load();
  await p.tick();
  p.document.getElementById("user").value = "alice";
  p.document.getElementById("pw").value = "guess";
  p.trusted(p.document.getElementById("login"), "submit", {}, p.impls.SubmitEventImpl);
  await p.tick(4);
  assert.equal(state.captures || 0, 0);
  p.window.navigator.userActivation.hasBeenActive = true;
  p.document.getElementById("pw").value = "real";
  p.trusted(p.document.getElementById("login"), "submit", {}, p.impls.SubmitEventImpl);
  await p.tick(4);
  assert.equal(state.captures, 1);
});

// ---- login-safety.js (L-12) ---------------------------------------------------

test("login-safety: card hints run on at most 256 characters per attribute", async () => {
  const huge = "cc-exp " + "a-".repeat(30000);
  const p = createPage({ html: `<form><input id="n" name="cardnumber"><input id="x" name="${huge}" placeholder="${huge}" aria-label="${huge}"></form>` });
  p.load();
  await p.tick();
  const S = p.S();
  const started = Date.now();
  const token = S.cardToken(p.document.getElementById("x"), true);
  assert.ok(Date.now() - started < 500, "no quadratic backtracking on page-sized attributes");
  assert.equal(token, "cc-exp", "the hint at the start still counts");
  assert.equal(S.cardToken(p.document.getElementById("n"), true), "cc-number");
});

// ---- passkeys (L-17) ----------------------------------------------------------

function bridge(isActive) {
  const window = new EventTarget();
  window.location = { origin: "https://login.example.test" };
  const sent = [];
  const chrome = { runtime: { sendMessage: msg => { sent.push(plain(msg)); return Promise.resolve({ ok: true }); } } };
  const context = vm.createContext({ window, location: window.location, chrome, Promise, Map, Object, JSON, String, CustomEvent,
    navigator: isActive === undefined ? {} : { userActivation: { isActive } } });
  context.globalThis = context;
  vm.runInContext(read("api.js"), context);
  vm.runInContext(read("webauthn-bridge.js"), context);
  const secret = "0123456789abcdef0123456789abcdef";
  window.dispatchEvent(new CustomEvent("lgk-passkey-hello", { detail: secret }));
  const request = kind => window.dispatchEvent(new CustomEvent(`lgk-passkey-req-${secret}`, { detail: JSON.stringify({ id: "r1", kind, options: {} }) }));
  return { sent, request };
}

test("passkey bridge reports a user activation only when the isolated world sees one", () => {
  const active = bridge(true); active.request("create");
  assert.equal(active.sent[0].user_activation, true);
  const idle = bridge(false); idle.request("create");
  assert.equal(idle.sent[0].user_activation, undefined);
  const old = bridge(undefined); old.request("create");
  assert.equal(old.sent[0].user_activation, undefined);
});

test("passkey page wrapper sends create without an activation straight to the browser", async () => {
  const window = new EventTarget();
  window.isSecureContext = true; window.location = { origin: "https://login.example.test" }; window.top = window;
  const state = { active: false };
  class UserActivation { get isActive() { return state.active; } }
  const natives = [];
  class CredentialsContainer {}
  Object.defineProperty(CredentialsContainer.prototype, "create", { writable: true, configurable: true, value: function create(o) { natives.push(o); return Promise.resolve("native-create"); } });
  Object.defineProperty(CredentialsContainer.prototype, "get", { writable: true, configurable: true, value: function get() { return Promise.resolve("native-get"); } });
  const credentials = new CredentialsContainer();
  const requests = [];
  window.addEventListener("lgk-passkey-hello", e => {
    const secret = e.detail;
    window.addEventListener(`lgk-passkey-req-${secret}`, r => {
      const data = JSON.parse(r.detail); requests.push(data);
      window.dispatchEvent(new CustomEvent(`lgk-passkey-res-${secret}`, { detail: JSON.stringify({ id: data.id, received: true }) }));
      window.dispatchEvent(new CustomEvent(`lgk-passkey-res-${secret}`, { detail: JSON.stringify({ id: data.id, result: { ok: false, error: "unreachable" } }) }));
    }, true);
    window.dispatchEvent(new CustomEvent(`lgk-passkey-ack-${secret}`));
  }, true);
  window.navigator = { credentials, userActivation: new UserActivation() };
  const context = vm.createContext({ window, navigator: window.navigator, location: window.location, UserActivation, CredentialsContainer,
    PublicKeyCredential: class {}, AuthenticatorAttestationResponse: class {}, AuthenticatorAssertionResponse: class {},
    DOMException, ArrayBuffer, Uint8Array, DataView, TextEncoder, btoa, atob, Promise, Map, WeakMap, Reflect, Object, Array, JSON, String, Error, TypeError,
    EventTarget, CustomEvent, crypto: globalThis.crypto, performance, setTimeout, clearTimeout, isSecureContext: true });
  vm.runInContext(read("webauthn-page.js"), context);
  const options = { publicKey: { rp: { id: "example.test", name: "Ex" }, user: { id: new Uint8Array([1]), name: "a", displayName: "A" },
    challenge: new Uint8Array(32).buffer, pubKeyCredParams: [{ type: "public-key", alg: -7 }] } };
  assert.equal(await credentials.create(options), "native-create");
  assert.equal(requests.length, 0, "no LocalGateKeys dialog without a click");
  state.active = true;
  assert.equal(await credentials.create(options), "native-create");
  assert.equal(requests.length, 1, "with a click the request is relayed");
  assert.equal(requests[0].kind, "create");
});

// ---- background.js (I-14, L-17 forwarding) ------------------------------------

function firefoxWorker() {
  let listener; const calls = []; const id = "testextension";
  const top = { url: PAGE, errorOccurred: false, parentFrameId: -1 };
  const ns = {
    runtime: { id, getManifest: () => ({ version: "0.4.5", permissions: [] }), getURL: p => `moz-extension://${id}/${p}`, sendMessage: () => Promise.resolve(),
      onMessage: { addListener: f => listener = f }, sendNativeMessage: (host, req) => { calls.push(plain(req)); return Promise.resolve({ ok: true }); } },
    webNavigation: { getFrame: async () => top, onDOMContentLoaded: { addListener() {} }, onCompleted: { addListener() {} }, onHistoryStateUpdated: { addListener() {} } },
    tabs: { get: async () => ({ active: true, discarded: false }), sendMessage: () => Promise.resolve() },
  };
  const context = vm.createContext({ browser: ns, URL, Set, Promise, setTimeout, clearTimeout, Uint8Array, btoa, fetch: async () => ({ ok: false }) });
  vm.runInContext(read("api.js"), context); vm.runInContext(read("background.js"), context);
  const send = req => new Promise(resolve => listener({ origin: ORIGIN, operation_id: "op1", ...req }, { id, tab: { id: 8 }, frameId: 0, url: PAGE }, resolve));
  return { calls, send };
}

test("background (Firefox): the per-document key from content.js is part of the context", async () => {
  const h = firefoxWorker();
  await h.send({ type: "pending_browser", document_key: KEY_A });
  await h.send({ type: "pending_browser", document_key: KEY_B });
  await h.send({ type: "pending_browser", document_key: "not-a-key" });
  assert.deepEqual(h.calls.map(c => JSON.parse(c.context)[1]), [`frame:0:${KEY_A}`, `frame:0:${KEY_B}`, "frame:0"]);
});

test("background: passkey requests forward user_activation only when it is exactly true", async () => {
  const h = firefoxWorker();
  await h.send({ type: "passkey_create_browser", passkey_protocol: 1, options: {}, user_activation: true });
  await h.send({ type: "passkey_create_browser", passkey_protocol: 1, options: {}, user_activation: "yes" });
  await h.send({ type: "passkey_create_browser", passkey_protocol: 1, options: {} });
  assert.deepEqual(h.calls.map(c => c.user_activation), [true, false, false]);
});

// ---- Firefox build (I-20) -----------------------------------------------------

test("the Firefox build ships no build scripts", () => {
  const { build, isBuildScript } = require(path.join(EXT, "build-firefox-manifest.cjs"));
  assert.equal(isBuildScript("build-safari-extension.cjs"), true);
  assert.equal(isBuildScript("background.js"), false);
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-ff-"));
  try {
    build(out);
    const shipped = fs.readdirSync(out);
    assert.deepEqual(shipped.filter(name => name.endsWith(".cjs")), []);
    assert.ok(shipped.includes("background.js") && shipped.includes("content.js") && shipped.includes("manifest.json"));
  } finally { fs.rmSync(out, { recursive: true, force: true }); }
});

// ---- Safari classify contract (iPhone stream H): no password comparison -------

test("Safari: classify answers new/exists/full/unavailable only; exists prompts, nothing reveals a password match", async () => {
  const h = safari({ native: () => ({ status: "exists" }) });
  const captured = await h.send({ type: "capture_browser", username: "alice", password: "guess" });
  assert.equal(captured.stored, true, "exists prompts");
  const pending = await h.send({ type: "pending_browser" });
  assert.equal(pending.status, "exists");
  const check = await h.send({ type: "check_browser", username: "alice", password: "guess" });
  assert.deepEqual({ status: check.status, match: check.match, prompt: check.prompt }, { status: "exists", match: false, prompt: true });
  for (const status of ["exact", "password_changed", "bogus"]) {
    const g = safari({ native: () => ({ status }) });
    const r = await g.send({ type: "check_browser", username: "alice", password: "pw" });
    assert.deepEqual({ status: r.status, match: r.match, prompt: r.prompt }, { status: "unavailable", match: false, prompt: false }, status);
  }
});

test("content: an exists prompt is a neutral save-or-update, never 'update saved password'", async () => {
  const { p } = await pageWithPrompt(() => ({ ok: true, pending: true, pending_token: "tok-1", username: "alice", status: "exists", age_ms: 0 }));
  assert.match(p.panelText(), /Save \/ update in LocalGateKeys\?/);
  assert.doesNotMatch(p.panelText(), /Update saved password/);
});
