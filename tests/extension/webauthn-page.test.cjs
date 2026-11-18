/* Passkey page wrapper (MAIN world) and its ISOLATED bridge, run in node:vm with stub browser APIs. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const EXT = path.join(__dirname, "..", "..", "browser-extension");
const pageSource = fs.readFileSync(path.join(EXT, "webauthn-page.js"), "utf8");
const bridgeSource = fs.readFileSync(path.join(EXT, "webauthn-bridge.js"), "utf8");
const shim = fs.readFileSync(path.join(EXT, "api.js"), "utf8");

const b64u = bytes => Buffer.from(bytes).toString("base64url");
const bytes = text => new TextEncoder().encode(text);

const HELLO = "lgk-passkey-hello", READY = "lgk-passkey-ready";

// A shared window (the DOM is shared by the MAIN and ISOLATED worlds; each
// script gets its own vm context, as each world has its own globals).
// top: "self" (top-level), a same-origin parent, a cross-origin parent or
// one whose location throws, as a cross-origin WindowProxy does.
function makeWindow({ secure = true, top = "self" } = {}) {
  const window = new EventTarget();
  window.isSecureContext = secure;
  window.location = { origin: "https://login.example.test" };
  if (top === "self") window.top = window;
  else if (top === "same-origin") window.top = { location: { origin: "https://login.example.test" } };
  else if (top === "cross-origin") window.top = { location: { origin: "https://shop.example.test" } };
  else if (top === "throws") window.top = { get location() { throw new DOMException("Blocked", "SecurityError"); } };
  return window;
}

// Fake timers. `delays` lists the delays of timers that were not cleared
// (the floor; the relay's ack and overall timers are cleared on a reply).
// Short timers fire on the next turn unless `hold`; timers of 5 s or more
// (the 120 s cap) fire only through timers.fire(ms).
function fakeTimers({ hold = false } = {}) {
  const entries = [];
  // A page clock the test can move forward (timers.offset).
  const timers = { offset: 0, now: () => performance.now() + timers.offset };
  const run = entry => { if (!entry.cleared && !entry.fired) { entry.fired = true; entry.fn(); } };
  Object.defineProperty(timers, "delays", { get: () => entries.filter(e => !e.cleared).map(e => e.ms) });
  return Object.assign(timers, {
    all: entries,
    setTimeout: (fn, ms) => {
      const entry = { fn, ms, cleared: false, fired: false };
      entries.push(entry);
      if (!hold && ms < 5000) setImmediate(() => run(entry));
      return entries.length;
    },
    clearTimeout: handle => { const entry = entries[handle - 1]; if (entry) entry.cleared = true; },
    fire: ms => { for (const entry of entries) if (entry.ms === ms) run(entry); },
  });
}

// activation: "active" (a click just happened), "idle", or "missing" (an
// engine without navigator.userActivation / UserActivation).
function runPage(window, { originals, timers, activation = "active" }) {
  class PublicKeyCredential {}
  class AuthenticatorAttestationResponse {}
  class AuthenticatorAssertionResponse {}
  // Real prototypes expose throwing getters; own properties must shadow them.
  for (const [cls, names] of [[AuthenticatorAttestationResponse, ["clientDataJSON", "attestationObject"]],
    [AuthenticatorAssertionResponse, ["clientDataJSON", "authenticatorData", "signature", "userHandle"]],
    [PublicKeyCredential, ["id", "rawId", "type"]]]) {
    for (const name of names) Object.defineProperty(cls.prototype, name, { get() { throw new TypeError("Illegal invocation"); }, configurable: true });
  }
  // Like the real interface: methods on the prototype, none on the instance.
  class CredentialsContainer {}
  Object.defineProperty(CredentialsContainer.prototype, "create", { writable: true, enumerable: true, configurable: true,
    value: function create(options) { originals.create.push(options); return Promise.resolve("native-create"); } });
  Object.defineProperty(CredentialsContainer.prototype, "get", { writable: true, enumerable: true, configurable: true,
    value: function get(options) { originals.get.push(options); return Promise.resolve("native-get"); } });
  originals.rawCreate = CredentialsContainer.prototype.create;
  originals.rawGet = CredentialsContainer.prototype.get;
  const credentials = new CredentialsContainer();
  // Like the real interface: the isActive getter lives on the prototype.
  class UserActivation {}
  Object.defineProperty(UserActivation.prototype, "isActive", { get: () => activation === "active", configurable: true, enumerable: true });
  window.navigator = activation === "missing" ? { credentials } : { credentials, userActivation: new UserActivation() };
  const context = vm.createContext({
    ...(activation === "missing" ? {} : { UserActivation }),
    window, navigator: window.navigator, location: window.location, PublicKeyCredential, CredentialsContainer,
    AuthenticatorAttestationResponse, AuthenticatorAssertionResponse, DOMException, ArrayBuffer, Uint8Array,
    DataView, TextEncoder, btoa, atob, Promise, Map, WeakMap, Reflect, Object, Array, JSON, String, Error, TypeError,
    EventTarget, CustomEvent, crypto: globalThis.crypto, performance: { now: timers.now }, setTimeout: timers.setTimeout, clearTimeout: timers.clearTimeout,
    isSecureContext: window.isSecureContext,
  });
  vm.runInContext(pageSource, context);
  return { credentials, context, classes: { PublicKeyCredential, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse, CredentialsContainer } };
}

// Stand-in for webauthn-bridge.js: completes the handshake (unless
// `handshake` is false), records requests and confirms each one (unless
// `received` is false).
function fakeBridge(window, { handshake = true, received = true } = {}) {
  const requests = [];
  let secret = null;
  const onHello = event => {
    if (secret || !handshake) return;
    secret = event.detail;
    window.addEventListener(`lgk-passkey-req-${secret}`, e => {
      const data = JSON.parse(e.detail);
      requests.push(data);
      if (received) window.dispatchEvent(new CustomEvent(`lgk-passkey-res-${secret}`, { detail: JSON.stringify({ id: data.id, received: true }) }));
    }, true);
    window.dispatchEvent(new CustomEvent(`lgk-passkey-ack-${secret}`));
  };
  window.addEventListener(HELLO, onHello, true);
  return {
    requests,
    secret: () => secret,
    announce: () => window.dispatchEvent(new CustomEvent(READY)),
    respond: (id, result) => window.dispatchEvent(new CustomEvent(`lgk-passkey-res-${secret}`, { detail: JSON.stringify({ id, result }) })),
  };
}

function page({ secure = true, pageFirst = false, holdTimers = false, top = "self", handshake = true, received = true, activation } = {}) {
  const window = makeWindow({ secure, top });
  const originals = { create: [], get: [] };
  const timers = fakeTimers({ hold: holdTimers });
  let fake, ran;
  if (pageFirst) { ran = runPage(window, { originals, timers, activation }); fake = fakeBridge(window, { handshake, received }); fake.announce(); }
  else { fake = fakeBridge(window, { handshake, received }); ran = runPage(window, { originals, timers, activation }); }
  const lastRequest = () => fake.requests.at(-1);
  const reply = result => fake.respond(lastRequest().id, result);
  return { window, ...ran, originals, timers, bridge: fake, posted: fake.requests, lastRequest, reply };
}

const createOptions = (extra = {}) => ({ publicKey: {
  rp: { id: "example.test", name: "Example" },
  user: { id: bytes("user-1"), name: "ada", displayName: "Ada" },
  challenge: new Uint8Array(32).fill(7).buffer,
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  excludeCredentials: [{ type: "public-key", id: bytes("old") }],
  authenticatorSelection: { userVerification: "required" },
  extensions: { credProps: true },
  ...extra,
} });
const getOptions = (extra = {}) => ({ publicKey: {
  rpId: "example.test", challenge: new Uint8Array(32).fill(9),
  allowCredentials: [{ type: "public-key", id: bytes("cred") }], userVerification: "discouraged", ...extra,
} });
const flush = () => new Promise(resolve => setImmediate(resolve));

const CREATED = {
  credential_id: b64u(bytes("cred-id")), client_data_json: b64u(bytes("{\"type\":\"webauthn.create\"}")),
  attestation_object: b64u(bytes("att")), authenticator_data: b64u(bytes("auth")),
  public_key_spki: b64u(bytes("spki")), public_key_algorithm: -7, transports: ["internal"], cred_props_rk: true,
};

test("publicKey create is relayed with base64url options and resolves a PublicKeyCredential", async () => {
  const p = page();
  const promise = p.credentials.create(createOptions());
  await flush();
  const req = p.lastRequest();
  assert.equal(req.kind, "create");
  assert.deepEqual(Object.keys(req).sort(), ["id", "kind", "options"]);
  const o = req.options;
  assert.equal(o.challenge, b64u(new Uint8Array(32).fill(7)));
  assert.equal(o.user.id, b64u(bytes("user-1")));
  assert.deepEqual(o.excludeCredentials, [{ type: "public-key", id: b64u(bytes("old")) }]);
  assert.deepEqual(o.pubKeyCredParams, [{ type: "public-key", alg: -7 }]);
  assert.equal(o.authenticatorSelection.userVerification, "required");
  assert.equal(o.extensions.credProps, true);
  p.reply({ ok: true, passkey_protocol: 1, credential: CREATED });
  const credential = await promise;
  assert.ok(credential instanceof p.classes.PublicKeyCredential);
  assert.ok(credential.response instanceof p.classes.AuthenticatorAttestationResponse);
  assert.equal(credential.id, CREATED.credential_id);
  assert.equal(credential.type, "public-key");
  assert.equal(credential.authenticatorAttachment, "platform");
  assert.deepEqual(new Uint8Array(credential.rawId), bytes("cred-id"));
  assert.deepEqual(new Uint8Array(credential.response.attestationObject), bytes("att"));
  assert.deepEqual(new Uint8Array(credential.response.getPublicKey()), bytes("spki"));
  assert.deepEqual(new Uint8Array(credential.response.getAuthenticatorData()), bytes("auth"));
  assert.equal(credential.response.getPublicKeyAlgorithm(), -7);
  assert.deepEqual([...credential.response.getTransports()], ["internal"]);
  assert.deepEqual(JSON.parse(JSON.stringify(credential.getClientExtensionResults())), { credProps: { rk: true } });
  const json = credential.toJSON();
  assert.equal(json.id, CREATED.credential_id);
  assert.equal(json.rawId, CREATED.credential_id);
  assert.equal(json.response.clientDataJSON, CREATED.client_data_json);
  assert.equal(json.response.attestationObject, CREATED.attestation_object);
  assert.equal(json.response.publicKey, CREATED.public_key_spki);
  assert.equal(p.originals.create.length, 0);
});

test("publicKey get resolves an assertion with userHandle and signature", async () => {
  const p = page();
  const promise = p.credentials.get(getOptions());
  await flush();
  const o = p.lastRequest().options;
  assert.equal(o.rpId, "example.test");
  assert.deepEqual(o.allowCredentials, [{ type: "public-key", id: b64u(bytes("cred")) }]);
  assert.equal(o.userVerification, "discouraged");
  p.reply({ ok: true, credential: { credential_id: b64u(bytes("cred")), client_data_json: b64u(bytes("{}")),
    authenticator_data: b64u(bytes("auth")), signature: b64u(bytes("sig")), user_handle: b64u(bytes("user-1")) } });
  const credential = await promise;
  assert.ok(credential.response instanceof p.classes.AuthenticatorAssertionResponse);
  assert.deepEqual(new Uint8Array(credential.response.signature), bytes("sig"));
  assert.deepEqual(new Uint8Array(credential.response.userHandle), bytes("user-1"));
  assert.deepEqual(JSON.parse(JSON.stringify(credential.getClientExtensionResults())), {});
  assert.equal(credential.toJSON().response.signature, b64u(bytes("sig")));
});

test("conditional get and non-publicKey calls go straight to the original", async () => {
  const p = page();
  const conditional = getOptions(); conditional.mediation = "conditional";
  assert.equal(await p.credentials.get(conditional), "native-get");
  assert.equal(await p.credentials.get({ password: true }), "native-get");
  assert.equal(await p.credentials.create({ password: {} }), "native-create");
  assert.equal(p.posted.length, 0);
  assert.equal(p.originals.get[0], conditional);
});

test("an engine without navigator.userActivation sends create straight to the browser, with no request and no floor", async () => {
  const p = page({ activation: "missing", holdTimers: true });
  const options = createOptions();
  assert.equal(await p.credentials.create(options), "native-create");
  assert.equal(p.originals.create[0], options);
  assert.equal(p.posted.length, 0);
  assert.equal(p.timers.all.length, 0, "no timer at all");
  // A get needs no activation and is still offered.
  const got = p.credentials.get(getOptions());
  await flush();
  assert.equal(p.posted.length, 1);
  p.reply({ ok: false, error: "system_provider" });
  assert.equal(await got, "native-get");
});

test("a create without a click goes straight to the browser", async () => {
  const p = page({ activation: "idle" });
  assert.equal(await p.credentials.create(createOptions()), "native-create");
  assert.equal(p.posted.length, 0);
});

test("an insecure context goes straight to the original", async () => {
  const p = page({ secure: false });
  assert.equal(await p.credentials.create(createOptions()), "native-create");
  assert.equal(p.posted.length, 0);
});

test("fallback and unknown replies call the original with the original options object", async () => {
  for (const result of [{ ok: false, error: "fallback" }, { ok: false, error: "unsupported_action" },
    { ok: false, error: "native_host_error" }, { ok: false, error: "destination_changed" }, null, { ok: true }]) {
    const p = page();
    const options = createOptions();
    const promise = p.credentials.create(options);
    await flush();
    p.reply(result);
    assert.equal(await promise, "native-create");
    assert.equal(p.originals.create[0], options);
  }
});

test("unserializable options fall back to the original", async () => {
  const p = page();
  const options = createOptions({ challenge: "not a buffer" });
  assert.equal(await p.credentials.create(options), "native-create");
  assert.equal(p.posted.length, 0);
});

test("user_cancelled, invalid_state and security_error reject with the matching DOMException", async () => {
  for (const [error, name] of [["user_cancelled", "NotAllowedError"], ["invalid_state", "InvalidStateError"],
    ["security_error", "SecurityError"]]) {
    const p = page();
    const promise = p.credentials.create(createOptions());
    await flush();
    p.reply({ ok: false, error });
    await assert.rejects(promise, e => e.name === name);
    assert.equal(p.originals.create.length, 0);
  }
});

test("an aborted signal rejects with AbortError and ignores the late reply", async () => {
  const p = page();
  const controller = new AbortController();
  const options = getOptions(); options.signal = controller.signal;
  const promise = p.credentials.get(options);
  await flush();
  controller.abort();
  await assert.rejects(promise, e => e.name === "AbortError");
  p.reply({ ok: true, credential: {} });
  assert.equal(p.originals.get.length, 0);

  const already = new AbortController(); already.abort();
  const early = getOptions(); early.signal = already.signal;
  await assert.rejects(p.credentials.get(early), e => e.name === "AbortError");
});

test("replies on another channel, for another id or malformed are ignored", async () => {
  const p = page();
  const promise = p.credentials.get(getOptions());
  await flush();
  const id = p.lastRequest().id;
  // Without the secret a page can only guess the event name.
  p.window.dispatchEvent(new CustomEvent("lgk-passkey-res-" + "0".repeat(32), { detail: JSON.stringify({ id, result: { ok: false, error: "user_cancelled" } }) }));
  p.window.dispatchEvent(new CustomEvent(`lgk-passkey-res-${p.bridge.secret()}`, { detail: "{not json" }));
  p.bridge.respond("other-id", { ok: false, error: "user_cancelled" });
  p.reply({ ok: false, error: "fallback" });
  assert.equal(await promise, "native-get");
});

function runBridge(window, response = { ok: true, credential: { id: 1 } }, selfOrigin = window.location.origin) {
  const sent = [];
  const chrome = { runtime: { sendMessage: msg => { sent.push(msg); return Promise.resolve(typeof response === "function" ? response(msg) : response); } } };
  const context = vm.createContext({ window, self: { origin: selfOrigin }, location: window.location, chrome, Promise, Map, Object, JSON, String, CustomEvent, Uint8Array, crypto: globalThis.crypto });
  context.globalThis = context;
  vm.runInContext(shim, context);
  vm.runInContext(bridgeSource, context);
  return { sent };
}

// The real pair, in both injection orders, with fake page timers.
function pair({ pageFirst = false, response, selfOrigin } = {}) {
  const window = makeWindow();
  const originals = { create: [], get: [] };
  const timers = fakeTimers();
  let ran, b;
  if (pageFirst) { ran = runPage(window, { originals, timers }); b = runBridge(window, response, selfOrigin); }
  else { b = runBridge(window, response, selfOrigin); ran = runPage(window, { originals, timers }); }
  return { window, originals, timers, sent: b.sent, ...ran };
}

const ASSERTION = { credential_id: b64u(bytes("cred")), client_data_json: b64u(bytes("{}")),
  authenticator_data: b64u(bytes("auth")), signature: b64u(bytes("sig")), user_handle: null };

for (const pageFirst of [false, true]) {
  test(`bridge relays a real passkey get end to end (${pageFirst ? "page script" : "bridge"} injected first)`, async () => {
    const p = pair({ pageFirst, response: { ok: true, credential: ASSERTION } });
    const credential = await p.credentials.get(getOptions());
    assert.ok(credential instanceof p.classes.PublicKeyCredential);
    assert.equal(p.sent.length, 1);
    const msg = p.sent[0];
    assert.equal(msg.type, "passkey_get_browser");
    assert.equal(msg.origin, "https://login.example.test");
    assert.equal(msg.passkey_protocol, 1);
    assert.match(msg.operation_id, /^pk-[0-9a-z]+-[0-9a-f]{12}$/);
    assert.equal(msg.options.rpId, "example.test");
    assert.equal(p.originals.get.length, 0);
    assert.deepEqual(p.timers.delays, [], "a success is never delayed");
  });
}

test("an opaque-origin document (sandboxed) never reaches the app: the browser's own WebAuthn answers", async () => {
  const p = pair({ response: { ok: true, credential: ASSERTION }, selfOrigin: "null" });
  assert.equal(await p.credentials.get(getOptions()), "native-get");
  assert.equal(p.sent.length, 0, "nothing is sent to the service worker");
  assert.equal(p.originals.get.length, 1);
});

test("a bridge that cannot read the document's origin answers at once and the browser's WebAuthn runs", async () => {
  const window = makeWindow();
  const sent = [];
  const chrome = { runtime: { sendMessage: msg => { sent.push(msg); return Promise.resolve({ ok: true, credential: ASSERTION }); } } };
  const self = { get origin() { throw new Error("no origin in this world"); } };
  const context = vm.createContext({ window, self, location: window.location, chrome, Promise, Map, Object, JSON, String, CustomEvent, Uint8Array, crypto: globalThis.crypto });
  context.globalThis = context;
  vm.runInContext(shim, context);
  vm.runInContext(bridgeSource, context);
  const timers = fakeTimers({ hold: true });
  const originals = { create: [], get: [] };
  const ran = runPage(window, { originals, timers });
  const promise = ran.credentials.get(getOptions());
  await flush();
  const floor = timers.delays.filter(ms => ms < 5000 && ms !== 1000);
  for (const ms of floor) timers.fire(ms);
  assert.equal(await promise, "native-get");
  assert.equal(sent.length, 0, "nothing is sent when the origin is unknown");
});

test("bridge takes the first hello only: a later page hello or READY learns and changes nothing", async () => {
  const p = pair({ response: { ok: false, error: "fallback" } });
  // A page script now tries to hijack the channel with its own secret...
  const forged = "f".repeat(32);
  const heard = [];
  p.window.addEventListener(HELLO, e => heard.push(e.detail));
  p.window.dispatchEvent(new CustomEvent(HELLO, { detail: forged }));
  p.window.dispatchEvent(new CustomEvent(`lgk-passkey-req-${forged}`, { detail: JSON.stringify({ id: "x1", kind: "get", options: {} }) }));
  // ...and asks the wrapper to repeat its hello.
  p.window.dispatchEvent(new CustomEvent(READY));
  await flush();
  assert.deepEqual(heard, [forged], "the wrapper does not answer READY after the handshake");
  assert.equal(p.sent.length, 0);
  // The real channel still works.
  assert.equal(await p.credentials.get(getOptions()), "native-get");
  assert.equal(p.sent.length, 1);
});

test("bridge ignores malformed hellos and requests", async () => {
  const window = makeWindow();
  const b = runBridge(window);
  for (const detail of [undefined, 7, "abc", "g".repeat(32), "A".repeat(32)]) window.dispatchEvent(new CustomEvent(HELLO, { detail }));
  const secret = "0123456789abcdef0123456789abcdef";
  window.dispatchEvent(new CustomEvent(HELLO, { detail: secret }));
  const req = detail => window.dispatchEvent(new CustomEvent(`lgk-passkey-req-${secret}`, { detail }));
  req("{bad json");
  req(JSON.stringify(null));
  req(JSON.stringify({ id: "r1", kind: "__proto__", options: {} }));
  req(JSON.stringify({ id: "x".repeat(65), kind: "get", options: {} }));
  req(JSON.stringify({ id: "", kind: "get", options: {} }));
  await flush();
  assert.equal(b.sent.length, 0);
  const replies = [];
  window.addEventListener(`lgk-passkey-res-${secret}`, e => replies.push(JSON.parse(e.detail)));
  req(JSON.stringify({ id: "r1", kind: "create", options: { challenge: "x" } }));
  await flush();
  const [created] = JSON.parse(JSON.stringify(b.sent));
  assert.match(created.document_key, /^[0-9a-f]{32}$/);
  assert.deepEqual(created, { type: "passkey_create_browser", origin: "https://login.example.test",
    operation_id: "pk-r1", passkey_protocol: 1, document_key: created.document_key, options: { challenge: "x" } });
  assert.equal(b.sent.length, 1);
  assert.deepEqual(replies, [{ id: "r1", received: true }, { id: "r1", result: { ok: true, credential: {} } }], "unknown credential fields stay in the bridge");
});

test("bridge hands the page only the credential fields and error codes the wrapper uses", async () => {
  const replyFor = async response => {
    const window = makeWindow();
    runBridge(window, response);
    const secret = "0123456789abcdef0123456789abcdef";
    window.dispatchEvent(new CustomEvent(HELLO, { detail: secret }));
    const replies = [];
    window.addEventListener(`lgk-passkey-res-${secret}`, e => replies.push(JSON.parse(e.detail)));
    window.dispatchEvent(new CustomEvent(`lgk-passkey-req-${secret}`, { detail: JSON.stringify({ id: "r1", kind: "get", options: {} }) }));
    await flush();
    return replies.find(r => r.result).result;
  };
  const credential = { credential_id: "AQ", client_data_json: "e30", authenticator_data: "AA", signature: "MEU", user_handle: "dQ",
    username: "alice@example.test", entry_id: "e1", vault: "personal" };
  assert.deepEqual(await replyFor({ ok: true, credential, message: "Signed in as alice", item_id: "e1" }),
    { ok: true, credential: { credential_id: "AQ", client_data_json: "e30", authenticator_data: "AA", signature: "MEU", user_handle: "dQ" } });
  for (const error of ["fallback", "system_provider", "security_error", "user_cancelled", "invalid_state"]) {
    assert.deepEqual(await replyFor({ ok: false, error, message: "LocalGateKeys is locked", profile: "Work" }), { ok: false, error });
  }
  for (const error of ["native_host_error", "locked", "destination_changed", 7, undefined]) {
    assert.deepEqual(await replyFor({ ok: false, error, message: "x" }), { ok: false, error: "bridge_error" }, String(error));
  }
});

test("neither script posts window messages or listens for them", () => {
  for (const src of [pageSource, bridgeSource]) {
    assert.doesNotMatch(src, /postMessage\s*\(/);
    assert.doesNotMatch(src, /addEventListener\(\s*["']message["']/);
  }
});

test("the wrapper looks native: prototype placement, attributes, name, length, toString", () => {
  const p = page();
  const proto = p.classes.CredentialsContainer.prototype;
  assert.deepEqual(Object.getOwnPropertyNames(p.credentials), [], "no own properties on navigator.credentials");
  for (const name of ["create", "get"]) {
    const d = Object.getOwnPropertyDescriptor(proto, name);
    assert.equal(d.writable, true); assert.equal(d.enumerable, true); assert.equal(d.configurable, true);
    assert.equal(d.value.name, name);
    assert.equal(d.value.length, 0);
    assert.equal(Object.prototype.hasOwnProperty.call(d.value, "prototype"), false);
    assert.throws(() => new d.value(), TypeError, "not a constructor, like the native");
  }
  // toString, from the page's own realm, reports the original's text.
  const originalGet = p.originals.rawGet.toString();
  const originalCreate = p.originals.rawCreate.toString();
  assert.equal(vm.runInContext("navigator.credentials.get.toString()", p.context), originalGet);
  assert.equal(vm.runInContext("Function.prototype.toString.call(navigator.credentials.create)", p.context), originalCreate);
  assert.equal(vm.runInContext("Function.prototype.toString.toString()", p.context), "function toString() { [native code] }");
  assert.equal(vm.runInContext("Function.prototype.toString.name + Function.prototype.toString.length", p.context), "toString0");
  assert.equal(vm.runInContext("Object.getOwnPropertyDescriptor(Function.prototype, 'toString').enumerable", p.context), false);
  assert.equal(vm.runInContext("(function f() { return 1; }).toString()", p.context), "function f() { return 1; }");
});

test("called on another object the wrapper behaves exactly like the original", async () => {
  const p = page();
  assert.equal(await p.classes.CredentialsContainer.prototype.get.call({}, getOptions()), "native-get");
  assert.equal(p.posted.length, 0);
});

test("the app's fallback, cancel and existing-passkey answers are held to the jittered floor; success and security_error are not", async () => {
  for (const [result, delayed] of [[{ ok: false, error: "fallback" }, true], [{ ok: false, error: "user_cancelled" }, true],
    [{ ok: false, error: "invalid_state" }, true], [null, false], [{ ok: false, error: "security_error" }, false]]) {
    const p = page();
    const promise = p.credentials.get(getOptions());
    await flush();
    p.reply(result);
    await promise.catch(() => {});
    if (delayed) {
      assert.equal(p.timers.delays.length, 1, JSON.stringify(result));
      assert.ok(p.timers.delays[0] > 800 && p.timers.delays[0] <= 1600, String(p.timers.delays[0]));
    } else {
      assert.deepEqual(p.timers.delays, []);
    }
  }
});

test("the floor is measured from the call, so a slow app adds no extra delay", async () => {
  const p = page();
  const promise = p.credentials.get(getOptions());
  await flush();
  p.timers.offset = 5000;
  p.reply({ ok: false, error: "fallback" });
  assert.equal(await promise, "native-get");
  assert.deepEqual(p.timers.delays, []);
});

test("aborting during the floor rejects with AbortError and never reaches the original", async () => {
  const p = page({ holdTimers: true });
  const controller = new AbortController();
  const options = getOptions(); options.signal = controller.signal;
  const promise = p.credentials.get(options);
  await flush();
  p.reply({ ok: false, error: "fallback" });
  await flush();
  assert.equal(p.timers.delays.length, 1, "the floor timer is pending");
  controller.abort();
  await assert.rejects(promise, e => e.name === "AbortError");
  assert.equal(p.originals.get.length, 0);
});

test("the page-first injection order completes the handshake too", async () => {
  const p = page({ pageFirst: true });
  const promise = p.credentials.get(getOptions());
  await flush();
  assert.equal(p.posted.length, 1);
  p.reply({ ok: true, credential: ASSERTION });
  assert.ok((await promise) instanceof p.classes.PublicKeyCredential);
});

test("an unreachable app, native host or bridge error goes to the browser at once, with no floor", async () => {
  for (const error of ["native_host_error", "agent_offline", "agent_state_missing", "timeout", "bridge_error",
    "destination_changed", "version_mismatch", "invalid_native_response"]) {
    const p = page({ holdTimers: true });
    const options = getOptions();
    const promise = p.credentials.get(options);
    await flush();
    p.reply({ ok: false, error, message: "x" });
    assert.equal(await promise, "native-get", error);
    assert.equal(p.originals.get[0], options);
    assert.deepEqual(p.timers.delays, [], `${error} is not held`);
  }
});

test("the real bridge answers a failing service worker with bridge_error, which is not held", async () => {
  for (const response of [() => { throw new Error("worker gone"); }, () => Promise.reject(new Error("no receiver")), () => undefined]) {
    const window = makeWindow();
    // The bridge dispatches through window.dispatchEvent; record its replies.
    const replies = [];
    window.dispatchEvent = function (event) {
      if (event.type.startsWith("lgk-passkey-res-")) replies.push(JSON.parse(event.detail));
      return EventTarget.prototype.dispatchEvent.call(this, event);
    };
    const originals = { create: [], get: [] };
    const timers = fakeTimers({ hold: true });
    const sent = [];
    const chrome = { runtime: { sendMessage: msg => { sent.push(msg); return response(msg); } } };
    const context = vm.createContext({ window, self: { origin: window.location.origin }, location: window.location, chrome, Promise, Map, Object, JSON, String, CustomEvent, Uint8Array, crypto: globalThis.crypto });
    context.globalThis = context;
    vm.runInContext(shim, context);
    vm.runInContext(bridgeSource, context);
    const ran = runPage(window, { originals, timers });
    assert.equal(await ran.credentials.create(createOptions()), "native-create");
    assert.equal(sent.length, 1);
    assert.deepEqual(replies.map(r => r.received === true ? "received" : r.result.error), ["received", "bridge_error"]);
    assert.deepEqual(timers.delays, [], "no floor for a bridge error");
  }
});

test("an app answer is held within the 0.9-1.6 s jitter range and then reaches the original", async () => {
  const p = page({ holdTimers: true });
  const promise = p.credentials.create(createOptions());
  await flush();
  p.reply({ ok: false, error: "fallback" });
  await flush();
  assert.equal(p.timers.delays.length, 1);
  const wait = p.timers.delays[0];
  assert.ok(wait > 800 && wait <= 1600, String(wait));
  assert.equal(p.originals.create.length, 0, "held");
  p.timers.fire(wait);
  assert.equal(await promise, "native-create");
});

test("the floor never starts after 1.5 s and never holds past 1.6 s from the call", async () => {
  // Elapsed 1.4 s: whatever remains is at most 0.2 s.
  {
    const p = page({ holdTimers: true });
    const rejected = assert.rejects(p.credentials.get(getOptions()), e => e.name === "NotAllowedError");
    await flush();
    p.timers.offset = 1400;
    p.reply({ ok: false, error: "user_cancelled" });
    await flush();
    const held = p.timers.delays;
    assert.ok(held.length <= 1);
    if (held.length) { assert.ok(held[0] <= 205, String(held[0])); p.timers.fire(held[0]); }
    await rejected;
  }
  // Elapsed 1.51 s: no floor at all, the original runs right away.
  {
    const p = page({ holdTimers: true });
    const promise = p.credentials.get(getOptions());
    await flush();
    p.timers.offset = 1510;
    p.reply({ ok: false, error: "fallback" });
    assert.equal(await promise, "native-get");
    assert.deepEqual(p.timers.delays, []);
  }
  assert.match(pageSource, /FLOOR_START_LIMIT_MS = 1500/);
  assert.match(pageSource, /HOLD_LIMIT_MS = 2500/);
});

test("a get from a cross-origin frame is held to the floor too (it can reach the app, so its answer reveals vault state)", async () => {
  for (const top of ["cross-origin", "throws", "same-origin", "self"]) {
    for (const error of ["fallback", "user_cancelled"]) {
      const p = page({ holdTimers: true, top });
      const promise = p.credentials.get(getOptions());
      await flush();
      p.reply({ ok: false, error });
      await flush();
      assert.equal(p.timers.delays.length, 1, `${top} ${error}`);
      assert.ok(p.timers.delays[0] > 800 && p.timers.delays[0] <= 1600, String(p.timers.delays[0]));
      p.timers.fire(p.timers.delays[0]);
      await promise.catch(() => {});
    }
  }
});

test("a create in a cross-origin frame gets no floor; a same-origin frame and the top frame do", async () => {
  for (const [top, held] of [["cross-origin", false], ["throws", false], ["same-origin", true], ["self", true]]) {
    const p = page({ holdTimers: true, top });
    const promise = p.credentials.create(createOptions());
    await flush();
    p.reply({ ok: false, error: "fallback" });
    await flush();
    assert.equal(p.timers.delays.length, held ? 1 : 0, top);
    if (held) p.timers.fire(p.timers.delays[0]);
    assert.equal(await promise, "native-create", top);
  }
});

test("without a handshake acknowledgement the original runs immediately and nothing is sent", async () => {
  const p = page({ handshake: false, holdTimers: true });
  const options = createOptions();
  assert.equal(await p.credentials.create(options), "native-create");
  assert.equal(p.originals.create[0], options);
  assert.equal(p.posted.length, 0);
  assert.equal(p.timers.all.length, 0, "no timer at all");
});

test("a bridge that never confirms the request (listeners gone, e.g. after document.open) falls back after the 1 s ack timeout", async () => {
  const p = page({ received: false, holdTimers: true });
  const options = getOptions();
  const promise = p.credentials.get(options);
  await flush();
  assert.equal(p.posted.length, 1);
  assert.equal(p.originals.get.length, 0, "still waiting for the ack");
  p.timers.fire(1000);
  assert.equal(await promise, "native-get");
  assert.equal(p.originals.get[0], options);
  assert.ok(p.timers.all.find(e => e.ms === 120000).cleared, "the cap timer is cleared");
  // A late reply changes nothing.
  p.reply({ ok: true, credential: ASSERTION });
  await flush();
  assert.equal(p.originals.get.length, 1);
  assert.deepEqual(p.timers.delays, [], "no floor timer");
});

test("a confirmed request with no reply is capped at 120 s, then goes to the browser", async () => {
  const p = page({ holdTimers: true });
  const promise = p.credentials.create(createOptions());
  await flush();
  assert.equal(p.posted.length, 1);
  assert.ok(p.timers.all.find(e => e.ms === 1000).cleared, "the received event cleared the ack timer");
  p.timers.fire(1000);
  await flush();
  assert.equal(p.originals.create.length, 0, "a cleared ack timer does not fall back");
  p.timers.fire(120000);
  assert.equal(await promise, "native-create");
  assert.deepEqual(p.timers.delays, [], "no floor after the cap");
});

test("an abort while waiting for the reply wins over the cap and clears both relay timers", async () => {
  const p = page({ holdTimers: true });
  const controller = new AbortController();
  const options = getOptions(); options.signal = controller.signal;
  const promise = p.credentials.get(options);
  await flush();
  controller.abort();
  await assert.rejects(promise, e => e.name === "AbortError");
  p.timers.fire(120000);
  await flush();
  assert.equal(p.originals.get.length, 0);
  assert.ok(p.timers.all.every(e => e.cleared), "both relay timers are cleared");
});

test("conditional create goes straight to the original too", async () => {
  const p = page();
  const options = createOptions(); options.mediation = "conditional";
  assert.equal(await p.credentials.create(options), "native-create");
  assert.equal(p.originals.create[0], options);
  assert.equal(p.posted.length, 0);
});

test("system_provider reply calls the original create/get immediately", async () => {
  for (const kind of ["create", "get"]) {
    // Held timers: any floor would leave a pending timer and never settle.
    const p = page({ holdTimers: true });
    const options = kind === "create" ? createOptions() : getOptions();
    const promise = p.credentials[kind](options);
    await flush();
    p.reply({ ok: false, error: "system_provider" });
    assert.equal(await promise, `native-${kind}`, kind);
    assert.equal(p.originals[kind].length, 1);
    assert.equal(p.originals[kind][0], options, "the page's own options object, unchanged");
    assert.deepEqual(p.timers.delays, [], `${kind}: no floor wait`);
  }
});

test("system_provider is not treated as user_cancelled", async () => {
  const p = page({ holdTimers: true });
  const promise = p.credentials.get(getOptions());
  await flush();
  p.reply({ ok: false, error: "system_provider" });
  // Resolves through the browser; a NotAllowedError would reject here.
  assert.equal(await promise, "native-get");
});

test("system_provider uses the originals captured at load, not a page-replaced method", async () => {
  const p = page({ holdTimers: true });
  const wrapped = p.credentials.create;
  const promise = wrapped.call(p.credentials, createOptions());
  await flush();
  const replaced = [];
  // The page swaps the prototype method after the call: the wrapper must not pick it up.
  p.classes.CredentialsContainer.prototype.create = options => { replaced.push(options); return Promise.resolve("page"); };
  p.reply({ ok: false, error: "system_provider" });
  assert.equal(await promise, "native-create");
  assert.equal(replaced.length, 0);
  assert.equal(p.originals.create.length, 1);
});

// ---- Two-step save (known limitation 2): the page confirms a created
// passkey before the site's code sees it, or discards it when it never will.
const outcomes = p => p.posted.filter(r => r.kind === "confirm" || r.kind === "discard");

test("a created passkey is confirmed, with only its id, before the site's code gets the credential", async () => {
  const p = page();
  let resolved = false;
  const promise = p.credentials.create(createOptions());
  promise.then(() => { resolved = true; });
  await flush();
  const id = p.lastRequest().id;
  const seen = [];
  p.window.addEventListener(`lgk-passkey-req-${p.bridge.secret()}`, e => { if (JSON.parse(e.detail).kind === "confirm") seen.push(resolved); }, true);
  p.reply({ ok: true, passkey_protocol: 1, credential: CREATED });
  const credential = await promise;
  assert.equal(credential.id, CREATED.credential_id);
  assert.deepEqual(outcomes(p), [{ id, kind: "confirm" }]);
  assert.deepEqual(seen, [false], "the confirm went out before the promise resolved");
  p.reply({ ok: true, passkey_protocol: 1, credential: CREATED });
  await flush();
  assert.equal(outcomes(p).length, 1, "reported once");
});

test("an abort after approval discards the credential that arrives late", async () => {
  const p = page();
  const controller = new AbortController();
  const options = createOptions(); options.signal = controller.signal;
  const promise = p.credentials.create(options);
  await flush();
  const id = p.lastRequest().id;
  controller.abort();
  await assert.rejects(promise, e => e.name === "AbortError");
  assert.deepEqual(outcomes(p), [], "nothing to report before the app answers");
  p.bridge.respond(id, { ok: true, credential: CREATED });
  assert.deepEqual(outcomes(p), [{ id, kind: "discard" }]);
  p.bridge.respond(id, { ok: true, credential: CREATED });
  assert.equal(outcomes(p).length, 1);
  assert.equal(p.originals.create.length, 0);
});

test("an abort that lands between the reply and the credential discards it and rejects", async () => {
  const p = page();
  const controller = new AbortController();
  const options = createOptions(); options.signal = controller.signal;
  const promise = p.credentials.create(options);
  await flush();
  const id = p.lastRequest().id;
  p.reply({ ok: true, credential: CREATED });
  controller.abort();
  await assert.rejects(promise, e => e.name === "AbortError");
  assert.deepEqual(outcomes(p), [{ id, kind: "discard" }]);
});

test("a create the page stopped waiting for (no ack in time) discards the late credential", async () => {
  const p = page({ received: false });
  const promise = p.credentials.create(createOptions());
  assert.equal(await promise, "native-create");
  const id = p.posted[0].id;
  p.bridge.respond(id, { ok: true, credential: CREATED });
  assert.deepEqual(outcomes(p), [{ id, kind: "discard" }]);
});

test("an unusable create reply is discarded and the browser's own create runs", async () => {
  for (const result of [{ ok: true }, { ok: true, credential: { ...CREATED, attestation_object: "%%%" } }]) {
    const p = page();
    const promise = p.credentials.create(createOptions());
    await flush();
    const id = p.lastRequest().id;
    p.reply(result);
    assert.equal(await promise, "native-create");
    assert.deepEqual(outcomes(p), [{ id, kind: "discard" }]);
  }
});

test("failed creates, gets and late failures report nothing", async () => {
  const p = page();
  const cancelled = p.credentials.create(createOptions());
  await flush();
  p.reply({ ok: false, error: "user_cancelled" });
  await assert.rejects(cancelled, e => e.name === "NotAllowedError");
  const got = p.credentials.get(getOptions());
  await flush();
  p.reply({ ok: true, credential: { credential_id: b64u(bytes("cred")), client_data_json: b64u(bytes("{}")),
    authenticator_data: b64u(bytes("auth")), signature: b64u(bytes("sig")), user_handle: null } });
  await got;
  const controller = new AbortController();
  const options = createOptions(); options.signal = controller.signal;
  const aborted = p.credentials.create(options);
  await flush();
  const id = p.lastRequest().id;
  controller.abort();
  await assert.rejects(aborted, e => e.name === "AbortError");
  p.bridge.respond(id, { ok: false, error: "fallback" });
  p.bridge.respond(id, { ok: true, credential: CREATED });
  assert.deepEqual(outcomes(p), [], "a create already answered with a failure is settled");
});

test("the real bridge forwards the page's confirm once, carrying only the create's operation id", async () => {
  const p = pair({ response: msg => (msg.type === "passkey_create_browser" ? { ok: true, credential: CREATED, item_id: "x" } : { ok: false, error: "not_found" }) });
  const credential = await p.credentials.create(createOptions());
  assert.equal(credential.id, CREATED.credential_id);
  await flush();
  assert.equal(p.sent.length, 2);
  const [create, confirm] = JSON.parse(JSON.stringify(p.sent));
  assert.equal(create.type, "passkey_create_browser");
  assert.equal(create.passkey_confirm, undefined, "the capability flag is the service worker's, not the bridge's");
  assert.match(create.document_key, /^[0-9a-f]{32}$/);
  assert.deepEqual(confirm, { type: "passkey_confirm_browser", origin: "https://login.example.test",
    operation_id: create.operation_id, passkey_protocol: 1, document_key: create.document_key });
});

test("the real bridge forwards the discard of an aborted create", async () => {
  let answer;
  const p = pair({ response: msg => (msg.type === "passkey_create_browser" ? new Promise(r => { answer = r; }) : { ok: true }) });
  const controller = new AbortController();
  const options = createOptions(); options.signal = controller.signal;
  const promise = p.credentials.create(options);
  await flush();
  controller.abort();
  await assert.rejects(promise, e => e.name === "AbortError");
  answer({ ok: true, credential: CREATED });
  await flush(); await flush();
  const sent = JSON.parse(JSON.stringify(p.sent));
  assert.deepEqual(sent.map(m => m.type), ["passkey_create_browser", "passkey_discard_browser"]);
  assert.equal(sent[1].operation_id, sent[0].operation_id);
  assert.match(sent[0].document_key, /^[0-9a-f]{32}$/);
  assert.equal(sent[1].document_key, sent[0].document_key, "the discard names the create's document");
});

function rawBridge(response) {
  const window = makeWindow();
  const b = runBridge(window, response);
  const secret = "0123456789abcdef0123456789abcdef";
  window.dispatchEvent(new CustomEvent(HELLO, { detail: secret }));
  const req = data => window.dispatchEvent(new CustomEvent(`lgk-passkey-req-${secret}`, { detail: JSON.stringify(data) }));
  const replies = [];
  window.addEventListener(`lgk-passkey-res-${secret}`, e => replies.push(JSON.parse(e.detail)));
  return { window, secret, req, replies, sent: b.sent };
}

test("the bridge forwards no confirm or discard for an id it never delivered, and at most one per create", async () => {
  const b = rawBridge(msg => (msg.type === "passkey_create_browser" ? { ok: true, credential: CREATED } : { ok: false, error: "not_found" }));
  b.req({ id: "r9", kind: "confirm" });
  b.req({ id: "r9", kind: "discard" });
  b.req({ id: "g1", kind: "get", options: {} });
  await flush();
  b.req({ id: "g1", kind: "confirm" });
  assert.deepEqual(b.sent.map(m => m.type), ["passkey_get_browser"], "a get or an unknown id is never confirmed");
  b.req({ id: "r1", kind: "create", options: {} });
  await flush();
  b.req({ id: "r1", kind: "confirm" });
  b.req({ id: "r1", kind: "confirm" });
  b.req({ id: "r1", kind: "discard" });
  await flush();
  assert.deepEqual(b.sent.map(m => m.type), ["passkey_get_browser", "passkey_create_browser", "passkey_confirm_browser"]);
  assert.ok(b.replies.every(r => r.id !== "r9"), "the page gets no answer to a report");
  assert.equal(b.replies.filter(r => r.id === "r1").length, 2, "received + result only");
});

test("the bridge discards a created passkey whose reply cannot reach the page whole", async () => {
  const malformed = rawBridge({ ok: true });
  malformed.req({ id: "r1", kind: "create", options: {} });
  await flush();
  assert.deepEqual(JSON.parse(JSON.stringify(malformed.sent.slice(1))), [{ type: "passkey_discard_browser",
    origin: "https://login.example.test", operation_id: "pk-r1", passkey_protocol: 1, document_key: malformed.sent[0].document_key }]);
  assert.deepEqual(malformed.replies.at(-1), { id: "r1", result: { ok: false, error: "bridge_error" } });
  // A get with the same reply is not a create: nothing to discard.
  const get = rawBridge({ ok: true });
  get.req({ id: "g1", kind: "get", options: {} });
  await flush();
  assert.deepEqual(get.sent.map(m => m.type), ["passkey_get_browser"]);
  // The frame is gone when the reply comes back: the event cannot be dispatched.
  const gone = rawBridge({ ok: true, credential: CREATED });
  const dispatch = gone.window.dispatchEvent.bind(gone.window);
  gone.window.dispatchEvent = event => {
    if (event.type.startsWith("lgk-passkey-res-") && JSON.parse(event.detail).result) throw new Error("frame gone");
    return dispatch(event);
  };
  gone.req({ id: "r2", kind: "create", options: {} });
  await flush();
  assert.deepEqual(gone.sent.map(m => m.type), ["passkey_create_browser", "passkey_discard_browser"]);
  gone.req({ id: "r2", kind: "confirm" });
  assert.equal(gone.sent.length, 2, "a discarded create cannot be confirmed afterwards");
});
