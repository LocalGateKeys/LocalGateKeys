/* Safari (iPhone) web resources: the generated resource folder, the Safari
 * manifest, background-safari.js message handling against a fake `browser`,
 * and the content.js capability switch / notices. No network. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const nodeCrypto = require("node:crypto");
const { createPage } = require("./helpers.cjs");

const ROOT = path.join(__dirname, "..", "..");
const EXT = path.join(ROOT, "browser-extension");
const RESOURCES = path.join(ROOT, "ios", "SafariSave", "Resources");
const BUILD = path.join(EXT, "build-safari-extension.cjs");
const loadBuild = () => require(BUILD);
const readSource = name => fs.readFileSync(path.join(EXT, name), "utf8");
const lf = text => text.replace(/\r\n/g, "\n");
const plain = value => JSON.parse(JSON.stringify(value));

const FULL_NOTICE = "Your free vault is full. Upgrade in LocalGateKeys to save more.";
const SAVED_NOTICE = "Saved. It will appear in LocalGateKeys next time you open it.";
const APP_ID = "app.localgatekeys.app";
const PAGE = "https://example.test/login";
const ORIGIN = "https://example.test";

// ---- generated resources and manifest

test("committed Safari resources match a fresh build", () => {
  const { build } = loadBuild();
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-safari-"));
  try {
    build(out);
    const fresh = fs.readdirSync(out).sort();
    assert.deepEqual(fs.readdirSync(RESOURCES).sort(), fresh, "same file list");
    for (const name of fresh) {
      assert.ok(fs.readFileSync(path.join(RESOURCES, name)).equals(fs.readFileSync(path.join(out, name))), `${name} differs: run npm run build:safari`);
    }
    // Deterministic: a second build is byte-identical.
    const again = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-safari-"));
    try {
      build(again);
      for (const name of fresh) assert.ok(fs.readFileSync(path.join(again, name)).equals(fs.readFileSync(path.join(out, name))), name);
    } finally { fs.rmSync(again, { recursive: true, force: true }); }
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test("safari manifest drops Chromium-only keys and keeps only storage and nativeMessaging", () => {
  const { safariManifest, SAFARI_FILES } = loadBuild();
  const source = JSON.parse(readSource("manifest.json"));
  const m = safariManifest(source);
  for (const key of ["key", "minimum_chrome_version", "web_accessible_resources", "browser_specific_settings", "action"]) {
    assert.equal(m[key], undefined, `${key} dropped`);
  }
  // The desktop icons, flat in the resources folder.
  assert.deepEqual(m.icons, { 16: "icon16.png", 32: "icon32.png", 48: "icon48.png", 128: "icon128.png" });
  assert.equal(m.manifest_version, 3);
  assert.equal(m.version, source.version);
  assert.deepEqual([...m.permissions].sort(), ["nativeMessaging", "storage"]);
  assert.deepEqual(m.host_permissions, ["http://*/*", "https://*/*"]);
  assert.deepEqual(m.background, { scripts: ["api.js", "background-safari.js"], persistent: false });
  assert.equal(m.content_scripts.length, 1, "passkey scripts stripped");
  const [cs] = m.content_scripts;
  assert.deepEqual(cs.js, ["api.js", "heuristics.js", "login-safety.js", "content.js"]);
  assert.equal(cs.all_frames, true);
  assert.equal(cs.run_at, "document_idle");
  assert.deepEqual(cs.matches, ["http://*/*", "https://*/*"]);
  assert.doesNotMatch(m.description, /Windows|PC/);
  assert.equal(source.key !== undefined && source.background.service_worker, "background.js", "input not mutated");
  const referenced = new Set([...m.background.scripts, ...cs.js]);
  for (const file of referenced) assert.ok(SAFARI_FILES.includes(file), file);
  for (const file of SAFARI_FILES) assert.ok(referenced.has(file), `${file} is not loaded`);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(RESOURCES, "manifest.json"), "utf8")), m);
});

test("shared scripts are byte-identical to browser-extension/", () => {
  const { SAFARI_FILES } = loadBuild();
  assert.deepEqual([...SAFARI_FILES].sort(), ["api.js", "background-safari.js", "content.js", "heuristics.js", "login-safety.js"]);
  for (const name of SAFARI_FILES) {
    assert.equal(fs.readFileSync(path.join(RESOURCES, name), "utf8"), lf(readSource(name)), name);
  }
  const { SAFARI_ICONS } = loadBuild();
  for (const name of Object.values(SAFARI_ICONS)) {
    assert.ok(fs.readFileSync(path.join(RESOURCES, name)).equals(fs.readFileSync(path.join(EXT, "icons", name))), name);
  }
  assert.deepEqual(fs.readdirSync(RESOURCES).sort(), [...SAFARI_FILES, ...Object.values(SAFARI_ICONS), "manifest.json"].sort(), "nothing else ships");
  assert.equal(fs.existsSync(path.join(RESOURCES, "background.js")), false, "no desktop background");
  assert.equal(fs.existsSync(path.join(RESOURCES, "popup.html")), false, "no popup");
});

// ---- background-safari.js with a fake `browser`

function safariHarness({ native = () => ({ status: "new" }), startClock = 1_700_000_000_000 } = {}) {
  const source = readSource("background-safari.js");
  const shim = readSource("api.js");
  const id = "safariext";
  const clock = { now: startClock };
  const calls = [], nudges = [], listeners = {};
  class FakeDate extends Date { static now() { return clock.now; } }
  const ns = {
    runtime: {
      id,
      getManifest: () => ({ version: "0.4.2" }),
      onMessage: { addListener: f => { listeners.message = f; } },
      sendMessage: () => Promise.resolve(),
      sendNativeMessage: (app, message) => { calls.push({ app, message: { ...message } }); return Promise.resolve(native(message)); },
    },
    tabs: {
      onUpdated: { addListener: f => { listeners.updated = f; } },
      onRemoved: { addListener: f => { listeners.removed = f; } },
      sendMessage: (tabId, message) => { nudges.push(plain({ tabId, message })); return Promise.resolve(); },
    },
  };
  const globals = {
    URL, Map, Set, Promise, setTimeout, clearTimeout, Uint8Array, Date: FakeDate,
    crypto: { getRandomValues: a => nodeCrypto.getRandomValues(a) },
    browser: ns,
  };
  const context = vm.createContext(globals);
  vm.runInContext(shim, context, { filename: "api.js" });
  vm.runInContext(source, context, { filename: "background-safari.js" });
  const sender = (url = PAGE, extra = {}) => ({ id, tab: { id: 8, url }, frameId: 0, url, ...extra });
  let op = 0;
  const send = (request, who = sender()) => new Promise(resolve => {
    // Replies are built in the vm realm: compare them as plain JSON.
    const keep = listeners.message({ origin: ORIGIN, operation_id: `op-${++op}`, ...request }, who, r => resolve(plain(r)));
    assert.equal(keep, true, "async reply");
  });
  return { calls, nudges, listeners, clock, sender, send, id };
}

async function captured(h, extra = {}) {
  const r = await h.send({ type: "capture_browser", username: "alice", password: "hunter2", ...extra });
  assert.equal(r.ok, true);
  assert.equal(r.stored, true);
  assert.match(r.pending_token, /^[0-9a-f]{32}$/);
  return r.pending_token;
}
async function gesture(h, operation_id) {
  const r = await h.send({ type: "begin_gesture_browser", user_gesture: true, operation_id });
  assert.equal(r.ok, true);
  assert.match(r.gesture_nonce, /^[0-9a-f]{32}$/);
  return r.gesture_nonce;
}

test("rejects a message whose sender origin differs from request.origin", async () => {
  const h = safariHarness();
  const r = await h.send({ type: "capture_browser", origin: "https://other.test", username: "alice", password: "pw" });
  assert.deepEqual({ ok: r.ok, error: r.error }, { ok: false, error: "origin_mismatch" });
  // Foreign extension, no tab, plain-http public page, cross-origin frame: all refused.
  assert.equal((await h.send({ type: "status" }, { ...h.sender(), id: "other" })).error, "untrusted_sender");
  assert.equal((await h.send({ type: "status" }, { id: h.id, url: PAGE })).error, "untrusted_sender");
  assert.equal((await h.send({ type: "capture_browser", origin: "http://example.test", username: "a", password: "b" }, h.sender("http://example.test/login"))).ok, false);
  const frame = h.sender(PAGE, { frameId: 3, tab: { id: 8, url: "https://top.test/" } });
  assert.equal((await h.send({ type: "capture_browser", username: "a", password: "b" }, frame)).ok, false);
  assert.equal(h.calls.length, 0, "nothing reached the native handler");
  // http on localhost is allowed.
  const local = await h.send({ type: "status", origin: "http://localhost:8080" }, h.sender("http://localhost:8080/login"));
  assert.equal(local.ok, true);
});

test("capture then pending returns the native status and a token", async () => {
  const h = safariHarness({ native: () => ({ status: "exists" }) });
  const token = await captured(h);
  assert.deepEqual(h.calls, [{ app: APP_ID, message: { action: "classify", origin: ORIGIN, username: "alice", password: "hunter2" } }]);
  const p = await h.send({ type: "pending_browser" });
  assert.equal(p.ok, true);
  assert.equal(p.pending, true);
  assert.equal(p.pending_token, token);
  assert.equal(p.username, "alice");
  assert.equal(p.status, "exists");
  assert.equal(p.password, undefined, "the password never goes back to the page");
  assert.equal(p.notice, undefined);
  // Another tab sees nothing.
  const other = await h.send({ type: "pending_browser" }, { ...h.sender(), tab: { id: 9, url: PAGE } });
  assert.equal(other.pending, false);
  // A finished load in that tab nudges the content script to re-check.
  h.listeners.updated(8, { status: "complete" }, { id: 8 });
  h.listeners.updated(8, { status: "loading" }, { id: 8 });
  assert.deepEqual(h.nudges, [{ tabId: 8, message: { command: "check_pending_save" } }]);
  // unavailable, and the retired password-comparison answers: no prompt, nothing stored.
  for (const status of ["unavailable", "exact", "password_changed"]) {
    const q = safariHarness({ native: () => ({ status }) });
    const r = await q.send({ type: "capture_browser", username: "alice", password: "hunter2" });
    assert.equal(r.stored, false, status);
    assert.equal((await q.send({ type: "pending_browser" })).pending, false, status);
  }
  // A native failure is "unavailable": no prompt.
  const broken = safariHarness({ native: () => { throw new Error("no handler"); } });
  assert.equal((await broken.send({ type: "capture_browser", username: "alice", password: "hunter2" })).stored, false);
});

test("a sign-in that lands on another subdomain of the same site keeps its capture", async () => {
  const LOGIN = "https://login.paddle.com", LANDING = "https://vendors.paddle.com";
  const sameSite = new Set([`${LANDING}|${LOGIN}`]);
  const h = safariHarness({ native: m => m.action === "same_site" ? { same: sameSite.has(`${m.origin}|${m.other}`) }
    : m.action === "save" ? { stored: true } : { status: "new" } });
  const at = origin => h.sender(`${origin}/`);
  const token = (await h.send({ type: "capture_browser", origin: LOGIN, username: "alice", password: "hunter2" }, at(LOGIN))).pending_token;
  assert.match(token, /^[0-9a-f]{32}$/);
  const p = await h.send({ type: "pending_browser", origin: LANDING }, at(LANDING));
  assert.equal(p.pending, true);
  assert.equal(p.pending_token, token);
  assert.equal(p.origin, LOGIN, "names the origin it is saved for");
  assert.equal(p.password, undefined);
  assert.deepEqual(h.calls.at(-1).message, { action: "same_site", origin: LANDING, other: LOGIN });
  // Its own origin needs no native check and carries no origin.
  const own = await h.send({ type: "pending_browser", origin: LOGIN }, at(LOGIN));
  assert.equal(own.pending, true);
  assert.equal(own.origin, undefined);
  // Another site, another tab: nothing.
  assert.equal((await h.send({ type: "pending_browser", origin: "https://evil.test" }, at("https://evil.test"))).pending, false);
  assert.equal((await h.send({ type: "pending_browser", origin: LANDING }, { ...at(LANDING), tab: { id: 9, url: `${LANDING}/` } })).pending, false);
  // Saved from the landing page, for the login page's origin.
  const nonce = await h.send({ type: "begin_gesture_browser", origin: LANDING, user_gesture: true, operation_id: "op-land" }, at(LANDING));
  const saved = await h.send({ type: "save_pending_browser", origin: LANDING, pending_token: token, user_gesture: true, gesture_nonce: nonce.gesture_nonce, operation_id: "op-land" }, at(LANDING));
  assert.equal(saved.ok, true);
  assert.deepEqual(h.calls.at(-1).message, { action: "save", origin: LOGIN, username: "alice", password: "hunter2", status: "new" });
  assert.equal((await h.send({ type: "pending_browser", origin: LOGIN }, at(LOGIN))).pending, false, "one attempt per capture");
});

test("the same-site handoff ends twelve seconds after the capture", async () => {
  const LOGIN = "https://login.paddle.com", LANDING = "https://vendors.paddle.com";
  const h = safariHarness({ native: m => m.action === "same_site" ? { same: true } : { status: "new" } });
  await h.send({ type: "capture_browser", origin: LOGIN, username: "alice", password: "hunter2" }, h.sender(`${LOGIN}/`));
  h.clock.now += 12_000;
  assert.equal((await h.send({ type: "pending_browser", origin: LANDING }, h.sender(`${LANDING}/`))).pending, false);
  assert.equal((await h.send({ type: "pending_browser", origin: LOGIN }, h.sender(`${LOGIN}/`))).pending, true, "still there for its own origin");
});

test("pending expires after ninety seconds (desktop parity, audit 2026-10-24 L-18)", async () => {
  const h = safariHarness();
  const token = await captured(h);
  h.clock.now += 89_000;
  const live = await h.send({ type: "pending_browser" });
  assert.equal(live.pending_token, token);
  assert.equal(live.age_ms, 89_000);
  h.clock.now += 1_001;
  assert.equal((await h.send({ type: "pending_browser" })).pending, false);
  const op = "op-late";
  const nonce = await gesture(h, op);
  const late = await h.send({ type: "save_pending_browser", pending_token: token, user_gesture: true, gesture_nonce: nonce, operation_id: op });
  assert.equal(late.ok, false);
  assert.equal(h.calls.filter(c => c.message.action === "save").length, 0);
});

test("save_pending_browser sends save to native and clears the pending entry", async () => {
  const h = safariHarness({ native: m => (m.action === "classify" ? { status: "new" } : { stored: true }) });
  const token = await captured(h);
  // No gesture flag: refused before the native handler.
  const bare = await h.send({ type: "save_pending_browser", pending_token: token });
  assert.equal(bare.error, "user_gesture_required");
  // A nonce minted for another operation does not count.
  const stray = await gesture(h, "op-other");
  const wrong = await h.send({ type: "save_pending_browser", pending_token: token, user_gesture: true, gesture_nonce: stray, operation_id: "op-save" });
  assert.equal(wrong.error, "gesture_nonce_invalid");
  assert.equal(h.calls.length, 1, "only the classify call so far");
  const nonce = await gesture(h, "op-save");
  const saved = await h.send({ type: "save_pending_browser", pending_token: token, user_gesture: true, gesture_nonce: nonce, operation_id: "op-save" });
  assert.equal(saved.ok, true);
  assert.deepEqual(h.calls[1], { app: APP_ID, message: { action: "save", origin: ORIGIN, username: "alice", password: "hunter2", status: "new" } });
  assert.equal((await h.send({ type: "pending_browser" })).pending, false, "cleared");
  // The nonce is single-use and the entry is gone: a second Save does nothing.
  const again = await h.send({ type: "save_pending_browser", pending_token: token, user_gesture: true, gesture_nonce: nonce, operation_id: "op-save" });
  assert.equal(again.ok, false);
  assert.equal(h.calls.length, 2);
  // Not now / clear drop the entry without a native call.
  const t2 = await captured(h);
  assert.equal((await h.send({ type: "discard_pending_browser", pending_token: "f".repeat(32) })).ok, true);
  assert.equal((await h.send({ type: "pending_browser" })).pending_token, t2, "a wrong token discards nothing");
  await h.send({ type: "discard_pending_browser", pending_token: t2 });
  assert.equal((await h.send({ type: "pending_browser" })).pending, false);
  await captured(h);
  assert.equal((await h.send({ type: "clear_pending_browser" })).ok, true);
  assert.equal((await h.send({ type: "pending_browser" })).pending, false);
  assert.equal(h.calls.filter(c => c.message.action === "save").length, 1);
});

test("unsupported types answer unsupported", async () => {
  const h = safariHarness();
  for (const type of ["begin_browser", "get_browser", "ping", "validate_browser", "begin_totp_browser", "begin_card_browser", "begin_identity_browser", "passkey_create_browser", "diagnostics", "nonsense"]) {
    assert.deepEqual(await h.send({ type }), { ok: false, error: "unsupported" }, type);
  }
  assert.equal(h.calls.length, 0);
});

test("status reports features.fill false", async () => {
  const h = safariHarness();
  const r = await h.send({ type: "status" });
  assert.equal(r.ok, true);
  assert.deepEqual(r.features, { fill: false });
  assert.equal(h.calls.length, 0, "status never reaches the native handler");
});

test("full status carries the full notice and no save", async () => {
  const h = safariHarness({ native: m => (m.action === "classify" ? { status: "full" } : { stored: true }) });
  const token = await captured(h);
  const p = await h.send({ type: "pending_browser" });
  assert.equal(p.status, "full");
  assert.equal(p.notice, FULL_NOTICE);
  const nonce = await gesture(h, "op-full");
  const r = await h.send({ type: "save_pending_browser", pending_token: token, user_gesture: true, gesture_nonce: nonce, operation_id: "op-full" });
  assert.equal(r.ok, false);
  assert.equal(r.message, FULL_NOTICE);
  assert.equal(h.calls.filter(c => c.message.action === "save").length, 0, "a full vault is never asked to save");
  const check = await h.send({ type: "check_browser", username: "alice", password: "hunter2" });
  assert.equal(check.status, "full");
  assert.equal(check.notice, FULL_NOTICE);
  // A save refused by the native side as full carries the same notice.
  const late = safariHarness({ native: m => (m.action === "classify" ? { status: "new" } : { stored: false, error: "full" }) });
  const t = await captured(late);
  const n = await gesture(late, "op-x");
  const refused = await late.send({ type: "save_pending_browser", pending_token: t, user_gesture: true, gesture_nonce: n, operation_id: "op-x" });
  assert.equal(refused.ok, false);
  assert.equal(refused.message, FULL_NOTICE);

  // content.js: the pending panel shows the notice and offers no Save button.
  const page = await capturedSafariPage({ pendingStatus: "full", notice: FULL_NOTICE });
  assert.equal(page.panelVisible(), true);
  assert.match(page.panelText(), new RegExp(FULL_NOTICE.replace(/\./g, "\\.")));
  const labels = panelButtons(page).map(b => b.textContent);
  assert.equal(labels.some(l => /^Save|^Update/.test(l)), false, labels.join(" | "));
  assert.ok(labels.includes("Not now"));
});

test("successful save carries the saved notice", async () => {
  const h = safariHarness({ native: m => (m.action === "classify" ? { status: "new" } : { stored: true }) });
  const token = await captured(h);
  const nonce = await gesture(h, "op-ok");
  const r = await h.send({ type: "save_pending_browser", pending_token: token, user_gesture: true, gesture_nonce: nonce, operation_id: "op-ok" });
  assert.equal(r.ok, true);
  assert.equal(r.notice, SAVED_NOTICE);
  // Manual save (field icon path) also answers with the notice.
  const n2 = await gesture(h, "op-manual");
  const manual = await h.send({ type: "save_browser", username: "bob", password: "pw2", user_gesture: true, gesture_nonce: n2, operation_id: "op-manual" });
  assert.equal(manual.ok, true);
  assert.equal(manual.notice, SAVED_NOTICE);
  assert.deepEqual(h.calls.at(-1).message, { action: "save", origin: ORIGIN, username: "bob", password: "pw2", status: "new" });

  // content.js: after Save the panel shows the notice instead of closing.
  const page = await capturedSafariPage({ pendingStatus: "new", saveReply: { ok: true, notice: SAVED_NOTICE } });
  assert.match(page.panelText(), /Save this login\?/);
  clickPanelButton(page, "Save login");
  await page.tick(8);
  assert.equal(page.panelVisible(), true);
  assert.match(page.panelText(), new RegExp(SAVED_NOTICE.replace(/\./g, "\\.")));
});

// ---- content.js against Safari-shaped replies

const LOGIN_FORM = `<form id="login" action="/session" method="post">
  <input id="user" type="text" name="username" autocomplete="username">
  <input id="pw" type="password" name="password">
  <button id="submit" type="submit">Sign in</button>
</form>`;
const SAFARI_MANIFEST = { version: "0.4.2", background: { scripts: ["api.js", "background-safari.js"], persistent: false } };
function panelButtons(p) { const root = p.shadows.get(p.panelHost()); return root ? Array.from(root.querySelectorAll("button")) : []; }
function clickPanelButton(p, text) {
  const button = panelButtons(p).find(b => b.textContent.includes(text));
  if (!button) throw new Error(`no panel button containing "${text}" in: ${panelButtons(p).map(b => b.textContent).join(" | ")}`);
  p.trusted(button, "click", { composed: true }, p.impls.MouseEventImpl);
}
function safariResponder({ pendingStatus = "new", notice, saveReply = { ok: true }, savedFor } = {}) {
  return async request => {
    switch (request.type) {
      case "status": return { ok: true, features: { fill: false } };
      case "begin_gesture_browser": return { ok: true, gesture_nonce: "d".repeat(32), gesture_expires_in: 30 };
      case "capture_browser": return { ok: true, stored: true, pending_token: "tok-s" };
      case "pending_browser": return { ok: true, pending: true, pending_token: "tok-s", username: "alice", status: pendingStatus, age_ms: 0, ...(notice ? { notice } : {}), ...(savedFor ? { origin: savedFor } : {}) };
      case "save_pending_browser": return { ...saveReply };
      case "discard_pending_browser": case "clear_pending_browser": return { ok: true };
      default: return { ok: false, error: "unsupported" };
    }
  };
}
async function safariPage(options) {
  const p = createPage(options);
  p.chrome.runtime.getManifest = () => SAFARI_MANIFEST;
  p.load();
  await p.tick(6);
  return p;
}
async function capturedSafariPage(responderOptions) {
  const p = await safariPage({ html: LOGIN_FORM, respond: safariResponder(responderOptions) });
  const d = p.document;
  d.getElementById("user").value = "alice";
  d.getElementById("pw").value = "hunter2";
  p.trusted(d.getElementById("login"), "submit", { submitter: d.getElementById("submit") }, p.impls.SubmitEventImpl);
  await p.tick(4);
  assert.equal(p.sent("capture_browser").length, 1);
  p.clock.now += 1000;
  d.getElementById("login").remove();
  await p.command("check_pending_save");
  await p.sleep(140);
  await p.tick(4);
  return p;
}

test("content.js shows no fill icon when features.fill is false", async () => {
  const p = await safariPage({ html: LOGIN_FORM + `<form><input id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6"></form>`, respond: safariResponder() });
  assert.equal(p.sent("status").length, 1, "the Safari background is asked once");
  assert.equal(p.fieldIcons().length, 0);
  assert.equal(p.otpIcons().length, 0);
  assert.equal(p.cardIcons().length, 0);
  assert.equal(p.identityIcons().length, 0);
  // A later DOM change does not bring the icons back.
  p.document.body.insertAdjacentElement("beforeend", Object.assign(p.document.createElement("input"), { type: "password" }));
  await p.sleep(80);
  await p.tick();
  assert.equal(p.fieldIcons().length, 0);
  // Fill commands are refused; nothing is asked of the background.
  for (const command of ["fill_current", "fill_totp", "fill_identity", "fill_card", "generate_new"]) {
    assert.equal((await p.command(command)).ok, false, command);
  }
  assert.equal(p.sent("begin_browser").length, 0);
  // The save prompt still works.
  const q = await capturedSafariPage({ pendingStatus: "exists" });
  assert.match(q.panelText(), /Save \/ update in LocalGateKeys\?/);
  assert.doesNotMatch(q.panelText(), /Update saved password/);
});

test("desktop background status has no features key", async () => {
  // content.js on the desktop: no Safari background in the manifest, so no
  // status probe is sent and the fill icons appear as before.
  const page = createPage({ html: LOGIN_FORM });
  page.load();
  await page.tick(6);
  assert.equal(page.messages.length, 0, "the desktop page sends nothing on load");
  assert.equal(page.fieldIcons().length, 1);
  // background.js answers a status request without any features switch.
  const source = readSource("background.js"), shim = readSource("api.js");
  let listener; const calls = [];
  const id = "testextension";
  const ns = {
    runtime: {
      id, getManifest: () => ({ version: "0.4.2", permissions: [] }), getURL: p => `chrome-extension://${id}/${p}`,
      onMessage: { addListener: f => { listener = f; } },
      sendNativeMessage: (host, req) => { calls.push(req); return Promise.resolve({ ok: true }); },
      sendMessage: () => Promise.resolve(),
    },
    webNavigation: { getFrame: async () => ({ documentId: "doc", url: PAGE, documentLifecycle: "active", errorOccurred: false, parentFrameId: -1 }) },
    tabs: { get: async () => ({ active: true, discarded: false }), sendMessage: () => Promise.resolve() },
  };
  const context = vm.createContext({ URL, Set, Promise, setTimeout, clearTimeout, Uint8Array, btoa, fetch: async () => ({ ok: false }), chrome: ns });
  vm.runInContext(shim, context); vm.runInContext(source, context);
  const reply = await new Promise(resolve => listener({ type: "status", origin: ORIGIN, operation_id: "op1" }, { id, tab: { id: 8 }, frameId: 0, url: PAGE, documentId: "doc" }, resolve));
  assert.equal(reply.ok, false);
  assert.equal("features" in reply, false);
  assert.equal("notice" in reply, false);
  assert.equal(calls.length, 0);
});

test("a landing page on another subdomain names the origin the login is saved for", async () => {
  const shown = async savedFor => {
    const p = createPage({ url: "https://vendors.example.test/home", html: "<p>Welcome back</p>",
      respond: safariResponder({ pendingStatus: "new", savedFor }) });
    p.chrome.runtime.getManifest = () => SAFARI_MANIFEST;
    p.load();
    await p.tick(6);
    p.clock.now += 1000;
    await p.sleep(360);
    await p.tick(4);
    assert.equal(p.panelVisible(), true);
    return p.panelText();
  };
  assert.match(await shown("https://login.example.test"), /https:\/\/login\.example\.test/);
  assert.match(await shown(undefined), /https:\/\/vendors\.example\.test/, "own origin by default");
  assert.doesNotMatch(await shown("javascript:alert(1)"), /javascript/, "only an origin is shown");
});

test("a fresh Safari document shows a waiting capture without a nudge", async () => {
  // Form-post login: the next document loads while the background already
  // holds the capture. tabs.onUpdated may never reach this content script.
  const p = createPage({ html: "<p>Welcome back</p>", respond: safariResponder({ pendingStatus: "new" }) });
  p.chrome.runtime.getManifest = () => SAFARI_MANIFEST;
  p.load();
  await p.tick(6);
  p.clock.now += 1000;
  await p.sleep(360);
  await p.tick(4);
  assert.ok(p.sent("pending_browser").length >= 1, "the new document asks for the waiting capture itself");
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /Save this login\?/);
});

test("desktop startup sends no extra pending checks", async () => {
  const p = createPage({ html: "<p>Welcome back</p>", respond: safariResponder({ pendingStatus: "new" }) });
  p.load();
  await p.tick(6);
  p.clock.now += 1000;
  await p.sleep(360);
  await p.tick(4);
  assert.equal(p.sent("pending_browser").length, 0);
  assert.equal(p.messages.length, 0);
});

test("full status always titles the panel Save this login", async () => {
  // Fresh document with a visible login surface and an old capture: the
  // outcome is uncertain, but a full vault still reads "Save this login?".
  const p = createPage({ html: LOGIN_FORM, respond: async request => (request.type === "pending_browser"
    ? { ok: true, pending: true, pending_token: "tok-f", username: "alice", status: "full", age_ms: 7000, notice: FULL_NOTICE }
    : safariResponder()(request)) });
  p.chrome.runtime.getManifest = () => SAFARI_MANIFEST;
  p.load();
  await p.tick(6);
  p.clock.now += 4000;
  await p.command("check_pending_save");
  await p.sleep(140);
  await p.tick(4);
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /Save this login\?/);
  assert.doesNotMatch(p.panelText(), /Did you just sign in\?/);
});
