/* Service worker: passkey allow-list, protocol pin, options cap and browser-derived context. No network. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const EXT = path.join(__dirname, "..", "..", "browser-extension");
const source = fs.readFileSync(path.join(EXT, "background.js"), "utf8");
const shim = fs.readFileSync(path.join(EXT, "api.js"), "utf8");

const TOP = "https://login.example.test/signin";
function harness({ response = { ok: true }, active = true } = {}) {
  let listener; const calls = []; const id = "testextension";
  const frames = { 0: { documentId: "doc-top", url: TOP, documentLifecycle: "active", errorOccurred: false, parentFrameId: -1 } };
  const tab = { active, discarded: false };
  const chrome = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: {
      id, getManifest: () => ({ version: "0.4.0", permissions: ["favicon"] }), getURL: p => `chrome-extension://${id}/${p}`,
      onMessage: { addListener: f => listener = f },
      sendNativeMessage: (host, req) => { calls.push({ host, req }); return Promise.resolve({ ...(typeof response === "function" ? response(req, frames) : response) }); },
    },
    webNavigation: { getFrame: async ({ frameId }) => frames[frameId], onDOMContentLoaded: { addListener() {} }, onCompleted: { addListener() {} }, onHistoryStateUpdated: { addListener() {} } },
    tabs: { get: async () => tab, sendMessage: () => Promise.resolve() },
  };
  const context = vm.createContext({ chrome, URL, Set, Promise, setTimeout, clearTimeout, Uint8Array, btoa, fetch: async () => ({ ok: false }) });
  vm.runInContext(shim, context); vm.runInContext(source, context);
  const sender = { id, tab: { id: 8 }, frameId: 0, documentId: "doc-top", url: TOP };
  const send = (req = {}) => new Promise(resolve => listener({ origin: "https://login.example.test", operation_id: "pk-r1", passkey_protocol: 1, ...req }, sender, resolve));
  return { calls, send, tab, frames };
}

test("passkey types require passkey_protocol 1 and forward browser-derived origin, context and options", async () => {
  const h = harness({ response: { ok: true, passkey_protocol: 1, credential: { credential_id: "x" } } });
  for (const type of ["passkey_create_browser", "passkey_get_browser"]) {
    const r = await h.send({ type, options: { challenge: "abc" } });
    assert.equal(r.ok, true, type);
  }
  assert.equal(h.calls.length, 2);
  for (const { req } of h.calls) {
    assert.equal(req.passkey_protocol, 1);
    assert.equal(req.protocol, 2);
    assert.equal(req.origin, "https://login.example.test");
    assert.deepEqual(JSON.parse(req.context), [8, "doc-top", "https://login.example.test", "pk-r1"]);
    assert.deepEqual(JSON.parse(JSON.stringify(req.options)), { challenge: "abc" });
  }
  const missing = await h.send({ type: "passkey_get_browser", passkey_protocol: undefined, options: {} });
  assert.equal(missing.error, "version_mismatch");
  assert.equal(h.calls.length, 2);
});

test("a spoofed page origin is refused", async () => {
  const h = harness();
  const r = await h.send({ type: "passkey_get_browser", origin: "https://evil.test", options: {} });
  assert.equal(r.error, "origin_mismatch");
  assert.equal(h.calls.length, 0);
});

test("oversized or non-object options answer fallback without native access", async () => {
  const h = harness();
  for (const options of [{ challenge: "x".repeat(70000) }, "text", [1, 2], null, undefined]) {
    const r = await h.send({ type: "passkey_create_browser", options });
    assert.equal(r.error, "fallback");
  }
  assert.equal(h.calls.length, 0);
});

test("an inactive tab answers destination_changed, which the page treats as fallback", async () => {
  const h = harness({ active: false });
  const r = await h.send({ type: "passkey_get_browser", options: {} });
  assert.equal(r.error, "destination_changed");
  assert.equal(h.calls.length, 0);
});

test("the app's system_provider answer is passed through unchanged", async () => {
  const h = harness({ response: { ok: false, error: "system_provider" } });
  for (const type of ["passkey_create_browser", "passkey_get_browser"]) {
    const r = await h.send({ type, options: { challenge: "abc" } });
    assert.deepEqual(JSON.parse(JSON.stringify(r)), { ok: false, error: "system_provider" }, type);
  }
  assert.equal(h.calls.length, 2);
});

// ---- Two-step save (known limitation 2).
test("a create announces the confirm capability, set by the worker whatever the page sends", async () => {
  const h = harness({ response: { ok: true, passkey_protocol: 1, credential: { credential_id: "x" } } });
  await h.send({ type: "passkey_create_browser", options: { challenge: "abc" }, passkey_confirm: false });
  await h.send({ type: "passkey_get_browser", options: { challenge: "abc" }, passkey_confirm: true });
  assert.equal(h.calls[0].req.passkey_confirm, true);
  assert.equal(h.calls[1].req.passkey_confirm, undefined);
});

test("confirm and discard forward only the protocol, origin and browser-derived context, even from a document that is leaving", async () => {
  for (const type of ["passkey_confirm_browser", "passkey_discard_browser"]) {
    const h = harness({ active: false, response: { ok: false, error: "not_found", message: "x" } });
    h.frames[0].documentLifecycle = "pending_deletion";
    const r = await h.send({ type, options: { challenge: "abc" }, passkey_confirm: true, item_id: "i1", entry_id: "e1" });
    assert.deepEqual(JSON.parse(JSON.stringify(r)), { ok: true }, "the page learns nothing from the app's answer");
    assert.equal(h.calls.length, 1, type);
    const req = JSON.parse(JSON.stringify(h.calls[0].req));
    assert.deepEqual(Object.keys(req).sort(), ["action", "context", "extension_version", "origin", "passkey_protocol", "protocol"]);
    assert.equal(req.action, type);
    assert.deepEqual(JSON.parse(req.context), [8, "doc-top", "https://login.example.test", "pk-r1"]);
    const missing = await h.send({ type, passkey_protocol: undefined });
    assert.equal(missing.error, "version_mismatch");
    const spoofed = await h.send({ type, origin: "https://evil.test" });
    assert.equal(spoofed.error, "origin_mismatch");
    assert.equal(h.calls.length, 1);
  }
});

test("a created passkey the worker drops because the document changed is discarded at once", async () => {
  const h = harness({ response: (req, frames) => {
    if (req.action === "passkey_create_browser") frames[0].documentId = "doc-next";
    return req.action === "passkey_create_browser" ? { ok: true, passkey_protocol: 1, credential: { credential_id: "x" } } : { ok: true };
  } });
  const r = await h.send({ type: "passkey_create_browser", options: { challenge: "abc" } });
  assert.equal(r.error, "destination_changed");
  assert.deepEqual(h.calls.map(c => c.req.action), ["passkey_create_browser", "passkey_discard_browser"]);
  assert.equal(h.calls[1].req.context, h.calls[0].req.context);
  assert.equal(h.calls[1].req.passkey_protocol, 1);
  // A failed create or a dropped get leaves nothing to discard.
  const failed = harness({ response: (req, frames) => { frames[0].documentId = "doc-next"; return { ok: false, error: "user_cancelled" }; } });
  await failed.send({ type: "passkey_create_browser", options: { challenge: "abc" } });
  const get = harness({ response: (req, frames) => { frames[0].documentId = "doc-next"; return { ok: true, credential: {} }; } });
  await get.send({ type: "passkey_get_browser", options: { challenge: "abc" } });
  assert.equal(failed.calls.length + get.calls.length, 2);
});
