/* Passkeys in Firefox: the real wrapper, bridge and service worker, wired together with Firefox-shaped
 * browser data (no sender.documentId, no frame documentId or documentLifecycle, the `browser` namespace). */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const EXT = path.join(__dirname, "..", "..", "browser-extension");
const read = name => fs.readFileSync(path.join(EXT, name), "utf8");
const pageSource = read("webauthn-page.js");
const bridgeSource = read("webauthn-bridge.js");
const shim = read("api.js");
const backgroundSource = read("background.js");

const ORIGIN = "https://login.example.test";
const URL_TOP = `${ORIGIN}/signin`;
const b64u = bytes => Buffer.from(bytes).toString("base64url");
const bytes = text => new TextEncoder().encode(text);
const flush = () => new Promise(resolve => setImmediate(resolve));
const plain = value => JSON.parse(JSON.stringify(value));

const CREATED = {
  credential_id: b64u(bytes("cred-id")), client_data_json: b64u(bytes("{\"type\":\"webauthn.create\"}")),
  attestation_object: b64u(bytes("att")), authenticator_data: b64u(bytes("auth")),
  public_key_spki: b64u(bytes("spki")), public_key_algorithm: -7, transports: ["internal"], cred_props_rk: true,
};
const ASSERTION = { credential_id: b64u(bytes("cred")), client_data_json: b64u(bytes("{}")),
  authenticator_data: b64u(bytes("auth")), signature: b64u(bytes("sig")), user_handle: null };

// Firefox's background page: `browser` namespace, getFrame with no documentId
// or documentLifecycle. `native` answers sendNativeMessage.
function firefoxBackground(native) {
  let listener; const calls = []; const id = "localgatekeys@localgatekeys.app";
  const frames = { 0: { url: URL_TOP, errorOccurred: false, parentFrameId: -1 } };
  const browser = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: {
      id, getManifest: () => ({ version: "0.4.12", permissions: [] }), getURL: p => `moz-extension://uuid/${p}`,
      sendMessage: () => Promise.resolve(), onMessage: { addListener: f => listener = f },
      sendNativeMessage: (host, req) => { calls.push(plain(req)); return Promise.resolve(native(req)); },
    },
    webNavigation: { getFrame: async ({ frameId }) => frames[frameId], onDOMContentLoaded: { addListener() {} },
      onCompleted: { addListener() {} }, onHistoryStateUpdated: { addListener() {} } },
    tabs: { get: async () => ({ active: true, discarded: false }), sendMessage: () => Promise.resolve() },
  };
  const context = vm.createContext({ browser, URL, Set, Promise, setTimeout, clearTimeout, Uint8Array, btoa, fetch: async () => ({ ok: false }) });
  vm.runInContext(shim, context); vm.runInContext(backgroundSource, context);
  // What Firefox reports for a content script in the top frame of tab 8: no documentId.
  const sender = { id, tab: { id: 8 }, frameId: 0, url: URL_TOP, origin: ORIGIN };
  const deliver = message => new Promise(resolve => listener(plain(message), sender, resolve));
  return { calls, deliver, contexts: () => calls.filter(c => c.action.startsWith("passkey_")).map(c => ({ action: c.action, context: JSON.parse(c.context) })) };
}

// One document in the frame: its own window, the MAIN-world wrapper and the
// ISOLATED bridge (each in its own vm context), the bridge messaging `bg`.
function loadDocument(bg, { activation = "active" } = {}) {
  const window = new EventTarget();
  window.isSecureContext = true;
  window.location = { origin: ORIGIN };
  window.top = window;
  class UserActivation {}
  Object.defineProperty(UserActivation.prototype, "isActive", { get: () => activation === "active", configurable: true });
  const userActivation = activation === "missing" ? undefined : new UserActivation();

  // ISOLATED world (document_start, before the wrapper here; the order does not matter).
  const sent = [];
  const browser = { runtime: { sendMessage: msg => { sent.push(plain(msg)); return bg.deliver(msg); } } };
  const isolated = vm.createContext({ window, self: { origin: ORIGIN }, location: window.location, browser, Promise, Map, Object, JSON, String,
    CustomEvent, Uint8Array, crypto: globalThis.crypto, navigator: userActivation ? { userActivation } : {} });
  isolated.globalThis = isolated;
  vm.runInContext(shim, isolated);
  vm.runInContext(bridgeSource, isolated);

  // MAIN world.
  const natives = { create: [], get: [] };
  class PublicKeyCredential {}
  class AuthenticatorAttestationResponse {}
  class AuthenticatorAssertionResponse {}
  class CredentialsContainer {}
  Object.defineProperty(CredentialsContainer.prototype, "create", { writable: true, enumerable: true, configurable: true,
    value: function create(options) { natives.create.push(options); return Promise.resolve("native-create"); } });
  Object.defineProperty(CredentialsContainer.prototype, "get", { writable: true, enumerable: true, configurable: true,
    value: function get(options) { natives.get.push(options); return Promise.resolve("native-get"); } });
  const credentials = new CredentialsContainer();
  window.navigator = userActivation ? { credentials, userActivation } : { credentials };
  const main = vm.createContext({
    ...(activation === "missing" ? {} : { UserActivation }),
    window, navigator: window.navigator, location: window.location, PublicKeyCredential, CredentialsContainer,
    AuthenticatorAttestationResponse, AuthenticatorAssertionResponse, DOMException, ArrayBuffer, Uint8Array,
    DataView, TextEncoder, btoa, atob, Promise, Map, WeakMap, Reflect, Object, Array, JSON, String, Error, TypeError,
    EventTarget, CustomEvent, crypto: globalThis.crypto, performance, setTimeout, clearTimeout, isSecureContext: true,
  });
  vm.runInContext(pageSource, main);
  return { credentials, sent, natives, PublicKeyCredential };
}

const createOptions = () => ({ publicKey: {
  rp: { id: "example.test", name: "Example" },
  user: { id: bytes("user-1"), name: "ada", displayName: "Ada" },
  challenge: new Uint8Array(32).fill(7).buffer,
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  authenticatorSelection: { userVerification: "required" },
} });
const getOptions = () => ({ publicKey: { rpId: "example.test", challenge: new Uint8Array(32).fill(9) } });

function nativeOk(req) {
  if (req.action === "passkey_create_browser") return { ok: true, passkey_protocol: 1, credential: CREATED };
  if (req.action === "passkey_get_browser") return { ok: true, passkey_protocol: 1, credential: ASSERTION };
  return { ok: true };
}

test("Firefox: create, confirm and get of one document carry one document key and build one context", async () => {
  const bg = firefoxBackground(nativeOk);
  const doc = loadDocument(bg);
  const credential = await doc.credentials.create(createOptions());
  assert.ok(credential instanceof doc.PublicKeyCredential);
  await flush(); await flush();
  const got = await doc.credentials.get(getOptions());
  assert.ok(got instanceof doc.PublicKeyCredential);
  assert.equal(doc.natives.create.length + doc.natives.get.length, 0, "the vault answered both");

  assert.deepEqual(doc.sent.map(m => m.type), ["passkey_create_browser", "passkey_confirm_browser", "passkey_get_browser"]);
  const keys = new Set(doc.sent.map(m => m.document_key));
  assert.equal(keys.size, 1, "one key for every message of the document");
  const [key] = keys;
  assert.match(key, /^[0-9a-f]{32}$/);

  const seen = bg.contexts();
  assert.deepEqual(seen.map(s => s.action), ["passkey_create_browser", "passkey_confirm_browser", "passkey_get_browser"]);
  for (const { context } of seen) {
    assert.equal(context[0], 8);
    assert.equal(context[1], `frame:0:${key}`, "Firefox: frame id plus the bridge's per-document key");
    assert.equal(context[2], ORIGIN);
  }
  const [create, confirm] = bg.calls.filter(c => c.action !== "passkey_get_browser");
  assert.equal(confirm.context, create.context, "the confirm names exactly the create's context");
});

test("Firefox: the discard of an aborted create names exactly the create's context", async () => {
  let answer;
  const bg = firefoxBackground(req => (req.action === "passkey_create_browser" ? new Promise(r => { answer = r; }) : { ok: true }));
  const doc = loadDocument(bg);
  const controller = new AbortController();
  const options = createOptions(); options.signal = controller.signal;
  const promise = doc.credentials.create(options);
  await flush(); await flush();
  controller.abort();
  await assert.rejects(promise, e => e.name === "AbortError");
  answer({ ok: true, passkey_protocol: 1, credential: CREATED });
  for (let i = 0; i < 6; i++) await flush();
  const [create, discard] = bg.calls;
  assert.deepEqual(bg.calls.map(c => c.action), ["passkey_create_browser", "passkey_discard_browser"]);
  assert.equal(discard.context, create.context);
  assert.equal(new Set(doc.sent.map(m => m.document_key)).size, 1);
});

test("Firefox: two documents loaded one after the other in one frame never share a passkey context", async () => {
  const bg = firefoxBackground(nativeOk);
  const first = loadDocument(bg);
  await first.credentials.get(getOptions());
  const second = loadDocument(bg);
  await second.credentials.get(getOptions());
  const [a, b] = bg.contexts().map(s => s.context);
  assert.equal(a[0], b[0], "same tab");
  assert.match(a[1], /^frame:0:[0-9a-f]{32}$/);
  assert.match(b[1], /^frame:0:[0-9a-f]{32}$/);
  assert.notEqual(a[1], b[1], "a new document draws a new key");
});

test("Firefox: without navigator.userActivation a create goes straight to the browser; a get is still offered", async () => {
  const bg = firefoxBackground(nativeOk);
  const doc = loadDocument(bg, { activation: "missing" });
  const options = createOptions();
  assert.equal(await doc.credentials.create(options), "native-create");
  assert.equal(doc.natives.create[0], options, "the page's own options object");
  assert.equal(doc.sent.length, 0, "nothing reaches the service worker");
  assert.ok((await doc.credentials.get(getOptions())) instanceof doc.PublicKeyCredential);
  assert.deepEqual(bg.calls.map(c => c.action), ["passkey_get_browser"]);
});

test("Firefox: a create without a click goes to the browser", async () => {
  const bg = firefoxBackground(nativeOk);
  const doc = loadDocument(bg, { activation: "idle" });
  assert.equal(await doc.credentials.create(createOptions()), "native-create");
  assert.equal(bg.calls.length, 0);
});

test("Chromium: documentId still wins over the bridge's key", async () => {
  // Same background, Chromium-shaped sender and frame: the key is ignored.
  let listener; const calls = []; const id = "x";
  const chrome = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: { id, getManifest: () => ({ version: "0.4.12", permissions: [] }), getURL: p => `chrome-extension://${id}/${p}`,
      onMessage: { addListener: f => listener = f }, sendNativeMessage: (h, req) => { calls.push(plain(req)); return Promise.resolve({ ok: true }); } },
    webNavigation: { getFrame: async () => ({ documentId: "doc-1", documentLifecycle: "active", url: URL_TOP, errorOccurred: false, parentFrameId: -1 }),
      onDOMContentLoaded: { addListener() {} }, onCompleted: { addListener() {} }, onHistoryStateUpdated: { addListener() {} } },
    tabs: { get: async () => ({ active: true, discarded: false }), sendMessage: () => Promise.resolve() },
  };
  const context = vm.createContext({ chrome, URL, Set, Promise, setTimeout, clearTimeout, Uint8Array, btoa, fetch: async () => ({ ok: false }) });
  vm.runInContext(shim, context); vm.runInContext(backgroundSource, context);
  await new Promise(resolve => listener({ type: "passkey_get_browser", origin: ORIGIN, operation_id: "pk-1", passkey_protocol: 1, options: {},
    document_key: "0123456789abcdef0123456789abcdef" }, { id, tab: { id: 8 }, frameId: 0, documentId: "doc-1", url: URL_TOP }, resolve));
  assert.equal(JSON.parse(calls[0].context)[1], "doc-1");
});
