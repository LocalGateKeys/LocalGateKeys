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
const RESOURCES_IOS = path.join(ROOT, "ios", "SafariSave", "Resources");
const RESOURCES_MAC = path.join(ROOT, "ios", "SafariMac", "Resources");
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

for (const [platform, RESOURCES] of [["ios", RESOURCES_IOS], ["macos", RESOURCES_MAC]]) test(`committed Safari resources (${platform}) match a fresh build`, () => {
  const { build } = loadBuild();
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-safari-"));
  try {
    build(out, platform);
    const fresh = fs.readdirSync(out).sort();
    assert.deepEqual(fs.readdirSync(RESOURCES).sort(), fresh, "same file list");
    const files = dir => fs.readdirSync(dir, { recursive: true, withFileTypes: true }).filter(e => e.isFile()).map(e => path.relative(dir, path.join(e.parentPath, e.name))).sort();
    assert.deepEqual(files(RESOURCES), files(out), "same file tree");
    for (const name of files(out)) {
      assert.ok(fs.readFileSync(path.join(RESOURCES, name)).equals(fs.readFileSync(path.join(out, name))), `${name} differs: run npm run build:safari`);
    }
    // Deterministic: a second build is byte-identical.
    const again = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-safari-"));
    try {
      build(again, platform);
      for (const name of files(out)) assert.ok(fs.readFileSync(path.join(again, name)).equals(fs.readFileSync(path.join(out, name))), name);
    } finally { fs.rmSync(again, { recursive: true, force: true }); }
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test("macOS manifest equals the iPhone one except for the description", () => {
  const { safariManifest } = loadBuild();
  const source = JSON.parse(readSource("manifest.json"));
  const ios = safariManifest(source, "ios");
  const mac = safariManifest(source, "macos");
  assert.match(ios.description, /^__MSG_ext_description_ios__$/);
  assert.match(mac.description, /^__MSG_ext_description_macos__$/);
  const en = require("./i18n-stub.cjs").MESSAGES;
  assert.match(en.ext_description_ios.message, /this device/);
  assert.match(en.ext_description_macos.message, /on this Mac\.$/);
  assert.deepEqual({ ...mac, description: "" }, { ...ios, description: "" });
  assert.throws(() => safariManifest(source, "windows"));
});

test("safari manifest drops Chromium-only keys and keeps only storage and nativeMessaging", () => {
  const { safariManifest, SAFARI_FILES } = loadBuild();
  const source = JSON.parse(readSource("manifest.json"));
  const m = safariManifest(source);
  for (const key of ["key", "minimum_chrome_version", "browser_specific_settings", "commands"]) {
    assert.equal(m[key], undefined, `${key} dropped`);
  }
  // The save panel frame: panel.html only, for web pages, without the
  // Chromium-only use_dynamic_url.
  assert.deepEqual(m.web_accessible_resources, [{ resources: ["panel.html"], matches: ["http://*/*", "https://*/*"] }]);
  // The toolbar button opens the Safari popup, never the desktop one.
  assert.deepEqual(m.action, { default_title: "__MSG_ext_name__", default_popup: "popup-safari.html",
    default_icon: { 16: "icon16.png", 32: "icon32.png", 48: "icon48.png" } });
  // The desktop icons, flat in the resources folder.
  assert.deepEqual(m.icons, { 16: "icon16.png", 32: "icon32.png", 48: "icon48.png", 128: "icon128.png" });
  assert.equal(m.manifest_version, 3);
  assert.equal(m.version, source.version);
  assert.deepEqual([...m.permissions].sort(), ["nativeMessaging", "storage", "webNavigation"]);
  assert.deepEqual(m.host_permissions, ["http://*/*", "https://*/*"]);
  assert.deepEqual(m.background, { scripts: ["api.js", "lookalike.js", "background-safari.js"], persistent: false });
  assert.equal(m.content_scripts.length, 1, "passkey scripts stripped");
  const [cs] = m.content_scripts;
  assert.deepEqual(cs.js, ["api.js", "heuristics.js", "login-safety.js", "content.js"]);
  assert.equal(cs.all_frames, true);
  assert.equal(cs.run_at, "document_idle");
  assert.deepEqual(cs.matches, ["http://*/*", "https://*/*"]);
  assert.doesNotMatch(require("./i18n-stub.cjs").MESSAGES.ext_description_ios.message, /Windows|PC/);
  assert.equal(source.key !== undefined && source.background.service_worker, "background.js", "input not mutated");
  const referenced = new Set([...m.background.scripts, ...cs.js]);
  for (const file of referenced) assert.ok(SAFARI_FILES.includes(file), file);
  for (const file of SAFARI_FILES) assert.ok(referenced.has(file), `${file} is not loaded`);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(RESOURCES_IOS, "manifest.json"), "utf8")), m);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(RESOURCES_MAC, "manifest.json"), "utf8")), safariManifest(source, "macos"));
});

for (const RESOURCES of [RESOURCES_IOS, RESOURCES_MAC]) test(`shared scripts are byte-identical to browser-extension/ (${path.basename(path.dirname(RESOURCES))})`, () => {
  const { SAFARI_FILES } = loadBuild();
  assert.deepEqual([...SAFARI_FILES].sort(), ["api.js", "background-safari.js", "content.js", "heuristics.js", "login-safety.js", "lookalike.js"]);
  for (const name of SAFARI_FILES) {
    assert.equal(fs.readFileSync(path.join(RESOURCES, name), "utf8"), lf(readSource(name)), name);
  }
  const { SAFARI_DATA, SAFARI_ICONS } = loadBuild();
  assert.deepEqual([...SAFARI_DATA].sort(), ["THIRD-PARTY-NOTICES.txt", "psl-min.json"]);
  for (const name of SAFARI_DATA) assert.equal(fs.readFileSync(path.join(RESOURCES, name), "utf8"), lf(readSource(name)), name);
  assert.match(fs.readFileSync(path.join(RESOURCES, "THIRD-PARTY-NOTICES.txt"), "utf8"), /https:\/\/mozilla\.org\/MPL\/2\.0\//, "the MPL notice ships with the suffix list");
  for (const name of Object.values(SAFARI_ICONS)) {
    assert.ok(fs.readFileSync(path.join(RESOURCES, name)).equals(fs.readFileSync(path.join(EXT, "icons", name))), name);
  }
  const { SAFARI_POPUP } = loadBuild();
  assert.deepEqual([...SAFARI_POPUP].sort(), ["popup-safari.html", "popup-safari.js"]);
  for (const name of SAFARI_POPUP) assert.equal(fs.readFileSync(path.join(RESOURCES, name), "utf8"), lf(readSource(name)), name);
  // The panel frame: panel.js unchanged; panel.html only with the flat icon
  // path and without the generator script (Safari has no generator).
  const { SAFARI_PANEL } = loadBuild();
  assert.deepEqual([...SAFARI_PANEL].sort(), ["panel.html", "panel.js"]);
  assert.equal(fs.readFileSync(path.join(RESOURCES, "panel.js"), "utf8"), lf(readSource("panel.js")));
  const html = fs.readFileSync(path.join(RESOURCES, "panel.html"), "utf8");
  assert.equal(html, lf(readSource("panel.html")).replace('url("icons/icon48.png")', 'url("icon48.png")').replace('<script src="generator.js"></script>\n', ""));
  assert.match(html, /url\("icon48\.png"\)/);
  assert.doesNotMatch(html, /icons\/|generator\.js/);
  for (const src of html.match(/src="[^"]+"/g)) assert.ok(fs.existsSync(path.join(RESOURCES, src.slice(5, -1))), `${src} ships`);
  assert.deepEqual(fs.readdirSync(RESOURCES).sort(), [...SAFARI_FILES, ...SAFARI_DATA, ...SAFARI_POPUP, ...SAFARI_PANEL, ...Object.values(SAFARI_ICONS), "manifest.json", "_locales"].sort(), "nothing else ships");
  assert.equal(fs.existsSync(path.join(RESOURCES, "background.js")), false, "no desktop background");
  assert.equal(fs.existsSync(path.join(RESOURCES, "popup.html")), false, "no desktop popup");
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
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
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

test("R1: a lookalike save is refused with the verdict and retried only with lookalike_confirmed", async () => {
  const pair = "0123456789abcdef0123456789abcdef";
  const refusal = { stored: false, error: "lookalike_site", site: "lookalike", site_reason: "other-suffix", site_matched: "example.com", site_pair: pair };
  const h = safariHarness({ native: m => (m.action === "classify" ? { status: "new" } : m.lookalike_confirmed === "true" ? { stored: true } : refusal) });
  const n1 = await gesture(h, "op-manual");
  const refused = await h.send({ type: "save_browser", username: "bob", password: "pw2", user_gesture: true, gesture_nonce: n1, operation_id: "op-manual" });
  assert.deepEqual(refused, { ok: false, error: "lookalike_site", kind: "lookalike", reason: "other-suffix", matched: "example.com", pair });
  assert.equal(h.calls.at(-1).message.lookalike_confirmed, undefined);
  const n2 = await gesture(h, "op-manual");
  const saved = await h.send({ type: "save_browser", username: "bob", password: "pw2", user_gesture: true, gesture_nonce: n2, operation_id: "op-manual", lookalike_confirmed: true });
  assert.equal(saved.ok, true);
  assert.equal(h.calls.at(-1).message.lookalike_confirmed, "true", "the native handler keeps String values only");
  // Only true confirms.
  const n3 = await gesture(h, "op-manual");
  await h.send({ type: "save_browser", username: "bob", password: "pw2", user_gesture: true, gesture_nonce: n3, operation_id: "op-manual", lookalike_confirmed: "yes" });
  assert.equal(h.calls.at(-1).message.lookalike_confirmed, undefined);
  // A waiting capture survives the refusal for the guard's one retry, then is gone.
  const token = await captured(h);
  const n4 = await gesture(h, "op-save");
  const first = await h.send({ type: "save_pending_browser", pending_token: token, user_gesture: true, gesture_nonce: n4, operation_id: "op-save" });
  assert.equal(first.error, "lookalike_site");
  assert.equal((await h.send({ type: "pending_browser" })).pending_token, token, "kept for the retry");
  const n5 = await gesture(h, "op-save");
  const retry = await h.send({ type: "save_pending_browser", pending_token: token, user_gesture: true, gesture_nonce: n5, operation_id: "op-save", lookalike_confirmed: true });
  assert.equal(retry.ok, true);
  assert.equal((await h.send({ type: "pending_browser" })).pending, false, "cleared after the save");
  // A refusal without a usable verdict is plain "unavailable".
  const bare = safariHarness({ native: m => (m.action === "classify" ? { status: "new" } : { stored: false, error: "lookalike_site" }) });
  const n6 = await gesture(bare, "op-x");
  const r = await bare.send({ type: "save_browser", username: "bob", password: "pw2", user_gesture: true, gesture_nonce: n6, operation_id: "op-x" });
  assert.equal(r.error, "unavailable");
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
function panelButtons(p) { const root = p.panelRoot(); return root ? Array.from(root.querySelectorAll("button")) : []; }
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
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
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

// ---- AI agent sign-in on the Mac (the one Safari fill): the user's icon click
// asks the app for an approved sign-in, a second click in the picker releases it.

const DOC = "a".repeat(32);
const OTHER_DOC = "b".repeat(32);
function agentNative({ offer = true, passkey = false, entries = ["e1"] } = {}) {
  return m => {
    if (m.action === "agent_status") return { ok: true, agent: true };
    if (m.action === "agent_offer") {
      if (passkey) return { ok: false, error: "agent_passkey", message: "Use the passkey sign-in." };
      if (!offer) return { ok: false, error: "not_found" };
      return { ok: true, agent: true, grant: "native-token", origin: ORIGIN,
        choices: entries.map(id => ({ entry_id: id, username: `user-${id}`, label: `Site ${id}`, favorite: false, require_master_password: false, match: "exact_origin" })) };
    }
    if (m.action === "agent_release") return { ok: true, username: `user-${m.entry_id}`, password: "s3cret" };
    return { status: "new" };
  };
}
async function docGesture(h, operation_id, document_key = DOC) {
  const r = await h.send({ type: "begin_gesture_browser", user_gesture: true, operation_id, document_key });
  assert.equal(r.ok, true);
  return r.gesture_nonce;
}

test("agent status asks the app once and is cached; status itself stays fill:false", async () => {
  const h = safariHarness({ native: agentNative() });
  assert.deepEqual(await h.send({ type: "agent_status_browser" }), { ok: true, agent: true });
  assert.deepEqual(await h.send({ type: "agent_status_browser" }), { ok: true, agent: true });
  assert.equal(h.calls.length, 1);
  assert.deepEqual(h.calls[0].message, { action: "agent_status" });
  h.clock.now += 11000;
  await h.send({ type: "agent_status_browser" });
  assert.equal(h.calls.length, 2, "asked again after 10 s");
  const off = safariHarness({ native: () => null });
  assert.deepEqual(await off.send({ type: "agent_status_browser" }), { ok: true, agent: false }, "no app answer: off");
  assert.deepEqual((await h.send({ type: "status" })).features, { fill: false });
});

test("agent offer: the trusted page URL goes to the app, the picker gets choices and a local token", async () => {
  const h = safariHarness({ native: agentNative({ entries: ["e1", "e2"] }) });
  const r = await h.send({ type: "fill_grant_browser", url: "https://evil.test/", document_key: DOC });
  assert.equal(r.ok, true);
  assert.match(r.grant, /^[0-9a-f]{32}$/);
  assert.notEqual(r.grant, "native-token", "the app's token stays in the background");
  assert.deepEqual(r.choices.map(c => c.entry_id), ["e1", "e2"]);
  assert.equal(r.choices.some(c => "password" in c), false);
  assert.deepEqual(h.calls[0].message, { action: "agent_offer", url: PAGE }, "the sender's URL, not the page-supplied one");
  // Nothing armed, a passkey grant, and no document key.
  const none = safariHarness({ native: agentNative({ offer: false }) });
  assert.deepEqual(await none.send({ type: "fill_grant_browser", document_key: DOC }), { ok: false, error: "not_found" });
  const pk = safariHarness({ native: agentNative({ passkey: true }) });
  assert.deepEqual(await pk.send({ type: "fill_grant_browser", document_key: DOC }), { ok: false, error: "agent_passkey", message: "Use the passkey sign-in." });
  const nodoc = safariHarness({ native: agentNative() });
  assert.deepEqual(await nodoc.send({ type: "fill_grant_browser" }), { ok: false, error: "not_found" });
  assert.equal(nodoc.calls.length, 0);
  // An offer for another origin is refused.
  const other = safariHarness({ native: m => m.action === "agent_offer" ? { ...agentNative()(m), origin: "https://other.test" } : null });
  assert.equal((await other.send({ type: "fill_grant_browser", document_key: DOC })).ok, false);
});

test("agent release: needs a gesture nonce, the offered login and the same document; one use", async () => {
  const h = safariHarness({ native: agentNative({ entries: ["e1", "e2"] }) });
  const { grant } = await h.send({ type: "fill_grant_browser", document_key: DOC });
  // No gesture: refused, and the offer stays.
  assert.equal((await h.send({ type: "get_browser", grant, entry_id: "e1", document_key: DOC })).error, "user_gesture_required");
  // Another document of the tab cannot use it.
  const n0 = await docGesture(h, "op-other", OTHER_DOC);
  assert.equal((await h.send({ type: "get_browser", grant, entry_id: "e1", user_gesture: true, gesture_nonce: n0, operation_id: "op-other", document_key: OTHER_DOC })).error, "unsupported");
  // A login that was not offered.
  const n1 = await docGesture(h, "op-1");
  assert.equal((await h.send({ type: "get_browser", grant, entry_id: "zz", user_gesture: true, gesture_nonce: n1, operation_id: "op-1", document_key: DOC })).error, "not_found");
  assert.equal(h.calls.filter(c => c.message.action === "agent_release").length, 0);
  const n2 = await docGesture(h, "op-2");
  const r = await h.send({ type: "get_browser", grant, entry_id: "e2", user_gesture: true, gesture_nonce: n2, operation_id: "op-2", document_key: DOC });
  assert.deepEqual(r, { ok: true, credential: { username: "user-e2", password: "s3cret" } });
  assert.deepEqual(h.calls.at(-1).message, { action: "agent_release", url: PAGE, grant: "native-token", entry_id: "e2" });
  // Released once: a second get_browser is refused, validate passes once.
  const n3 = await docGesture(h, "op-3");
  assert.equal((await h.send({ type: "get_browser", grant, entry_id: "e2", user_gesture: true, gesture_nonce: n3, operation_id: "op-3", document_key: DOC })).error, "unsupported");
  assert.deepEqual(await h.send({ type: "validate_browser", grant, entry_id: "e2", document_key: DOC }), { ok: true });
  assert.equal((await h.send({ type: "validate_browser", grant, entry_id: "e2", document_key: DOC })).error, "unsupported");
  // An offer expires after 60 s.
  const late = safariHarness({ native: agentNative() });
  const offered = await late.send({ type: "fill_grant_browser", document_key: DOC });
  late.clock.now += 61000;
  const n4 = await docGesture(late, "op-4");
  assert.equal((await late.send({ type: "get_browser", grant: offered.grant, entry_id: "e1", user_gesture: true, gesture_nonce: n4, operation_id: "op-4", document_key: DOC })).error, "unsupported");
  // cancel_browser drops a waiting offer.
  const c = safariHarness({ native: agentNative() });
  const o = await c.send({ type: "fill_grant_browser", document_key: DOC });
  assert.deepEqual(await c.send({ type: "cancel_browser", grant: o.grant, document_key: DOC }), { ok: true });
  assert.equal((await c.send({ type: "validate_browser", grant: o.grant, entry_id: "e1", document_key: DOC })).error, "unsupported");
});

function agentSafariResponder({ agent = true, offer = true, state = {} } = {}) {
  state.releases = [];
  const base = safariResponder();
  return async request => {
    switch (request.type) {
      case "agent_status_browser": return { ok: true, agent };
      case "fill_grant_browser": return offer ? { ok: true, grant: "c".repeat(32), choices: [{ entry_id: "e1", username: "alice", label: "Example", favorite: false, match: "exact_origin" }] } : { ok: false, error: "not_found" };
      case "get_browser": state.releases.push(request); return { ok: true, credential: { username: "alice", password: "s3cret" } };
      case "validate_browser": return { ok: true };
      default: return base(request);
    }
  };
}
const clickFieldIcon = p => p.trusted(p.shadows.get(p.fieldIcons()[0]).querySelector("button"), "click", { composed: true }, p.impls.MouseEventImpl);

test("content.js with agents on: only the sign-in icon, released by the user's two clicks", async () => {
  const state = {};
  const p = await safariPage({ html: LOGIN_FORM + `<form><input id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6"></form>`, respond: agentSafariResponder({ state }) });
  await p.tick(6);
  assert.equal(p.sent("agent_status_browser").length, 1);
  assert.ok(p.fieldIcons().length >= 1, "the sign-in icon is back");
  assert.equal(p.otpIcons().length, 0, "nothing else fills");
  assert.equal(p.cardIcons().length, 0);
  assert.equal(p.identityIcons().length, 0);
  assert.equal(p.sent("fill_grant_browser").length, 0, "never asked on load");
  for (const command of ["fill_current", "fill_totp", "generate_new"]) assert.equal((await p.command(command)).ok, false, command);
  clickFieldIcon(p);
  await p.tick(8);
  assert.equal(p.sent("fill_grant_browser").length, 1);
  assert.equal(state.releases.length, 0, "even one approved login waits for the pick");
  const row = panelButtons(p).find(b => !/Cancel/.test(b.textContent));
  p.trusted(row, "click", { composed: true }, p.impls.MouseEventImpl);
  await p.tick(10);
  assert.equal(state.releases.length, 1);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  assert.equal(p.sent("begin_browser").length, 0);
});

test("content.js with agents on and nothing approved: the icon click fills nothing", async () => {
  const p = await safariPage({ html: LOGIN_FORM, respond: agentSafariResponder({ offer: false }) });
  await p.tick(6);
  clickFieldIcon(p);
  await p.tick(8);
  assert.equal(p.sent("begin_browser").length, 0, "no normal fill on Safari");
  assert.equal(p.panelVisible(), true);
  assert.equal(p.document.getElementById("pw").value, "");
  const off = await safariPage({ html: LOGIN_FORM, respond: agentSafariResponder({ agent: false }) });
  await off.tick(6);
  assert.equal(off.fieldIcons().length, 0, "agents off: no icon");
});

test("a password-only capture (no username) is never kept, so it can never be saved as a new login", async () => {
  const h = safariHarness({ native: m => (m.action === "classify" ? { status: "new" } : { stored: true }) });
  const r = await h.send({ type: "capture_browser", username: "", password: "N3w-pw!" });
  assert.deepEqual({ ok: r.ok, stored: r.stored, status: r.status }, { ok: true, stored: false, status: "username_required" });
  assert.equal(r.pending_token, undefined);
  assert.equal(h.calls.length, 0, "not even classified: no save path, no probe");
  assert.equal((await h.send({ type: "pending_browser" })).pending, false);
  // A named capture on the same page still prompts.
  await captured(h);
  assert.equal((await h.send({ type: "pending_browser" })).pending, true);
});

test("content.js on Safari: a change-password form without a username shows no prompt and saves nothing", async () => {
  const sent = [];
  const p = await safariPage({ html: `<form id="change"><input id="old" type="password" autocomplete="current-password"><input id="new1" type="password" autocomplete="new-password"><button id="go" type="submit">Change</button></form>`,
    respond: async request => {
      sent.push(request.type);
      if (request.type === "status") return { ok: true, features: { fill: false } };
      if (request.type === "capture_browser") return { ok: true, stored: false, status: "username_required" };
      if (request.type === "pending_browser") return { ok: true, pending: false };
      return null;
    } });
  const d = p.document;
  d.getElementById("old").value = "old"; d.getElementById("new1").value = "N3w-pw!";
  p.trusted(d.getElementById("change"), "submit", { submitter: d.getElementById("go") }, p.impls.SubmitEventImpl);
  await p.tick(6); d.getElementById("change").remove();
  await p.sleep(1200); await p.tick(8);
  assert.equal(p.panelVisible(), false);
  assert.ok(!sent.includes("save_pending_browser") && !sent.includes("save_browser"));
});

// ---- "filled": the app's AutoFill extension just filled this sign-in

test("filled: no prompt, no pending capture, and the same answers as unavailable", async () => {
  const answers = { h: "filled", u: "unavailable" };
  const harness = name => safariHarness({ native: m => (m.action === "classify" ? { status: answers[name] } : m.action === "save" ? { stored: true } : {}) });
  const h = harness("h"), u = harness("u");
  const capture = { type: "capture_browser", username: "alice", password: "hunter2" };
  const r = await h.send(capture);
  assert.deepEqual(r, { ok: true, stored: false });
  assert.deepEqual(r, await u.send(capture), "the page gets the unavailable answer");
  assert.equal((await h.send({ type: "pending_browser" })).pending, false);
  h.listeners.updated(8, { status: "complete" }, { id: 8 });
  assert.deepEqual(h.nudges, [], "nothing waits, so no re-check nudge");
  // check_browser: no prompt, no notice, no error; identical to unavailable.
  const check = { type: "check_browser", username: "alice", password: "hunter2" };
  const c = await h.send(check);
  assert.deepEqual(c, { ok: true, status: "unavailable", match: false, prompt: false });
  assert.deepEqual(c, await u.send(check));
  // An older capture of this tab (a mistyped try before AutoFill) is dropped,
  // for filled and unavailable alike.
  for (const [name, q] of [["h", h], ["u", u]]) {
    const was = answers[name];
    answers[name] = "exists";
    await captured(q, { password: "typo" });
    answers[name] = was;
    assert.deepEqual(await q.send(capture), { ok: true, stored: false });
    assert.equal((await q.send({ type: "pending_browser" })).pending, false, name);
  }
  // Only classify reached the app: no save, no inbox count (badge).
  assert.deepEqual([...new Set(h.calls.map(call => call.message.action))], ["classify"]);
  // A later sign-in the app answers "exists" prompts as before.
  answers.h = "exists";
  const token = await captured(h);
  const p = await h.send({ type: "pending_browser" });
  assert.equal(p.pending_token, token);
  assert.equal(p.status, "exists");
});

test("filled on an explicit Save click: saved as an update, never refused as unavailable", async () => {
  const h = safariHarness({ native: m => (m.action === "classify" ? { status: "filled" } : { stored: true }) });
  const save = { type: "save_browser", username: "alice", password: "hunter2", user_gesture: true, operation_id: "op-manual" };
  assert.equal((await h.send({ ...save, gesture_nonce: "e".repeat(32) })).error, "gesture_nonce_invalid");
  assert.equal(h.calls.length, 0, "no gesture, nothing asked of the app");
  const r = await h.send({ ...save, gesture_nonce: await gesture(h, "op-manual") });
  assert.deepEqual(r, { ok: true, notice: SAVED_NOTICE });
  assert.deepEqual(h.calls.map(call => call.message), [
    { action: "classify", origin: ORIGIN, username: "alice", password: "hunter2" },
    { action: "save", origin: ORIGIN, username: "alice", password: "hunter2", status: "exists" },
  ]);
});

test("content.js with the Safari background: a filled sign-in shows nothing, an exists one still prompts", async () => {
  const signIn = async status => {
    const h = safariHarness({ native: m => (m.action === "classify" ? { status } : {}) });
    const sent = [];
    const p = await safariPage({ html: LOGIN_FORM, respond: request => { sent.push(request.type); return h.send(request); } });
    const d = p.document;
    d.getElementById("user").value = "alice";
    d.getElementById("pw").value = "hunter2";
    p.trusted(d.getElementById("login"), "submit", { submitter: d.getElementById("submit") }, p.impls.SubmitEventImpl);
    await p.tick(6);
    p.clock.now += 1000;
    d.getElementById("login").remove();
    await p.command("check_pending_save");
    await p.sleep(1400);
    await p.tick(8);
    return { p, sent, h };
  };
  const filled = await signIn("filled");
  assert.equal(filled.sent.filter(t => t === "capture_browser").length, 1);
  assert.equal(filled.h.calls.filter(c => c.message.action === "classify" && c.message.password).length, 1, "one classify for one sign-in");
  assert.equal(filled.p.panelVisible(), false, "no prompt and no error panel");
  assert.ok(!filled.sent.includes("save_pending_browser") && !filled.sent.includes("save_browser"));
  const exists = await signIn("exists");
  assert.equal(exists.p.panelVisible(), true);
  assert.match(exists.p.panelText(), /Save \/ update in LocalGateKeys\?/);
});

// ---- toolbar button: popup messages and badge

function popupHarness({ native = () => ({ count: "0" }), blocked = [] } = {}) {
  const id = "safariext";
  const calls = [], badges = [], listeners = {};
  const store = { automatic_save_blocked_origins: [...blocked] };
  const clock = { now: 1_700_000_000_000 };
  class FakeDate extends Date { static now() { return clock.now; } }
  const ns = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: {
      id,
      getManifest: () => ({ version: "0.4.12" }),
      getURL: p => `safari-web-extension://${id}/${p}`,
      onMessage: { addListener: f => { listeners.message = f; } },
      onStartup: { addListener: f => { listeners.startup = f; } },
      onInstalled: { addListener: f => { listeners.installed = f; } },
      sendMessage: () => Promise.resolve(),
      sendNativeMessage: (app, message) => { calls.push({ ...message }); return Promise.resolve(native(message)); },
    },
    storage: { local: {
      get: defaults => Promise.resolve(plain({ ...defaults, ...store })),
      set: values => { Object.assign(store, plain(values)); return Promise.resolve(); },
    } },
    action: {
      setBadgeText: d => { badges.push(d.text); return Promise.resolve(); },
      setBadgeBackgroundColor: () => Promise.resolve(),
    },
    tabs: {
      onUpdated: { addListener: () => {} },
      onRemoved: { addListener: () => {} },
      onActivated: { addListener: f => { listeners.activated = f; } },
      sendMessage: () => Promise.resolve(),
    },
  };
  const context = vm.createContext({ URL, Map, Set, Promise, setTimeout, clearTimeout, Uint8Array, Date: FakeDate,
    crypto: { getRandomValues: a => nodeCrypto.getRandomValues(a) }, browser: ns });
  vm.runInContext(readSource("api.js"), context, { filename: "api.js" });
  vm.runInContext(readSource("background-safari.js"), context, { filename: "background-safari.js" });
  const POPUP = { id, url: `safari-web-extension://${id}/popup-safari.html` };
  const send = (request, who = POPUP) => new Promise(resolve => {
    assert.equal(listeners.message(request, who, r => resolve(plain(r))), true);
  });
  return { calls, badges, listeners, store, clock, send, POPUP, id };
}
const settle = () => new Promise(r => setImmediate(r));

test("popup state: the inbox count and the site switch, nothing about any login", async () => {
  const h = popupHarness({ native: m => (m.action === "pending_count" ? { count: "2" } : {}), blocked: ["https://blocked.test"] });
  const r = await h.send({ type: "popup_state_safari", origin: ORIGIN });
  assert.deepEqual(r, { ok: true, count: 2, can_open: false, offer_save: true });
  assert.deepEqual(h.calls, [{ action: "pending_count" }, { action: "open_app_supported" }], "the native requests carry no site");
  assert.deepEqual(h.badges, ["2"]);
  assert.deepEqual(await h.send({ type: "popup_state_safari", origin: "https://blocked.test" }), { ok: true, count: 2, can_open: false, offer_save: false });
  // A page the extension does not save on (plain http, no origin) gets no switch.
  assert.deepEqual(await h.send({ type: "popup_state_safari", origin: "http://example.test" }), { ok: true, count: 2, can_open: false });
  assert.deepEqual(await h.send({ type: "popup_state_safari" }), { ok: true, count: 2, can_open: false });
});

test("popup count: anything but digits is 0 and clears the badge", async () => {
  for (const reply of [{ count: "0" }, { count: 3 }, { count: "-1" }, { count: "2 logins" }, { error: "unsupported" }, null]) {
    const h = popupHarness({ native: () => reply });
    assert.equal((await h.send({ type: "popup_state_safari", origin: ORIGIN })).count, 0, JSON.stringify(reply));
    assert.deepEqual(h.badges, [""]);
  }
});

test("popup switch edits the same never-on-this-site list content.js reads", async () => {
  const h = popupHarness({ blocked: ["https://keep.test"] });
  assert.deepEqual(await h.send({ type: "popup_offer_save_safari", origin: ORIGIN, enabled: false }), { ok: true, offer_save: false });
  assert.deepEqual(h.store.automatic_save_blocked_origins, ["https://keep.test", ORIGIN]);
  await h.send({ type: "popup_offer_save_safari", origin: ORIGIN, enabled: false });
  assert.deepEqual(h.store.automatic_save_blocked_origins, ["https://keep.test", ORIGIN], "no duplicate");
  assert.deepEqual(await h.send({ type: "popup_offer_save_safari", origin: ORIGIN, enabled: true }), { ok: true, offer_save: true });
  assert.deepEqual(h.store.automatic_save_blocked_origins, ["https://keep.test"]);
  assert.equal((await h.send({ type: "popup_offer_save_safari", origin: "http://example.test", enabled: false })).ok, false);
  assert.equal((await h.send({ type: "popup_offer_save_safari", origin: ORIGIN, enabled: "no" })).ok, false);
  assert.deepEqual(h.store.automatic_save_blocked_origins, ["https://keep.test"]);
  assert.equal(h.calls.length, 0, "the switch never reaches the app");
});

test("two concurrent switches for different sites both stay off", async () => {
  const h = popupHarness({ blocked: ["https://keep.test"] });
  const [a, b] = await Promise.all([
    h.send({ type: "popup_offer_save_safari", origin: "https://a.test", enabled: false }),
    h.send({ type: "popup_offer_save_safari", origin: "https://b.test", enabled: false }),
  ]);
  assert.deepEqual([a, b], [{ ok: true, offer_save: false }, { ok: true, offer_save: false }]);
  assert.deepEqual(h.store.automatic_save_blocked_origins, ["https://keep.test", "https://a.test", "https://b.test"]);
});

test("a full never-on-this-site list refuses a new site and keeps every entry", async () => {
  const full = Array.from({ length: 2000 }, (_, i) => `https://s${i}.test`);
  const h = popupHarness({ blocked: full });
  const r = await h.send({ type: "popup_offer_save_safari", origin: ORIGIN, enabled: false });
  assert.equal(r.ok, false);
  assert.equal(r.error, "full");
  assert.match(r.message, /2,000 sites/);
  assert.deepEqual(h.store.automatic_save_blocked_origins, full, "the oldest site is not dropped");
  const page = { id: h.id, tab: { id: 4, url: PAGE }, frameId: 0, url: PAGE };
  assert.equal((await h.send({ type: "never_site_browser", origin: ORIGIN, operation_id: "op-1" }, page)).ok, false);
  assert.deepEqual(h.store.automatic_save_blocked_origins, full);
  // A site already on the list, and turning one back on, still work.
  assert.deepEqual(await h.send({ type: "popup_offer_save_safari", origin: "https://s0.test", enabled: false }), { ok: true, offer_save: false });
  assert.deepEqual(await h.send({ type: "popup_offer_save_safari", origin: "https://s0.test", enabled: true }), { ok: true, offer_save: true });
  assert.deepEqual(await h.send({ type: "popup_offer_save_safari", origin: ORIGIN, enabled: false }), { ok: true, offer_save: false });
  assert.equal(h.store.automatic_save_blocked_origins.length, 2000);
});

test("the save prompt's Never on this site goes through the same single writer", async () => {
  const h = popupHarness();
  const page = { id: h.id, tab: { id: 4, url: PAGE }, frameId: 0, url: PAGE };
  assert.deepEqual(await h.send({ type: "never_site_browser", origin: ORIGIN, operation_id: "op-1" }, page), { ok: true });
  assert.deepEqual(h.store.automatic_save_blocked_origins, [ORIGIN]);
});

test("popup messages are only taken from the popup page", async () => {
  const h = popupHarness({ native: () => ({ opened: true, count: "1" }) });
  // A content script (it always has a tab) cannot use the popup's requests, even with the popup's URL.
  const page = { id: h.id, tab: { id: 4, url: PAGE }, frameId: 0, url: PAGE };
  assert.equal((await h.send({ type: "popup_open_app_safari", origin: ORIGIN, operation_id: "x" }, page)).error, "unsupported");
  assert.equal((await h.send({ type: "popup_state_safari" }, { ...h.POPUP, tab: { id: 4, url: PAGE } })).ok, false);
  assert.equal((await h.send({ type: "popup_state_safari" }, { ...h.POPUP, id: "other" })).error, "untrusted_sender");
  assert.equal((await h.send({ type: "popup_state_safari" }, { id: h.id, url: `safari-web-extension://${h.id}/other.html` })).error, "untrusted_sender");
  assert.equal(h.calls.length, 0);
  // The popup itself cannot reach the page requests.
  assert.equal((await h.send({ type: "capture_browser", origin: ORIGIN, username: "a", password: "b", operation_id: "y" })).error, "unsupported");
});

test("can_open is the native handler's answer: only an explicit supported true shows the button", async () => {
  const mac = popupHarness({ native: m => (m.action === "open_app_supported" ? { supported: true } : { count: "0" }) });
  assert.equal((await mac.send({ type: "popup_state_safari" })).can_open, true);
  for (const reply of [{ error: "unsupported" }, { supported: "true" }, { supported: false }, { opened: true }, null]) {
    const other = popupHarness({ native: m => (m.action === "open_app_supported" ? reply : { count: "0" }) });
    assert.equal((await other.send({ type: "popup_state_safari" })).can_open, false, JSON.stringify(reply));
  }
});

test("Open LocalGateKeys asks the native handler and reports only whether it opened", async () => {
  const h = popupHarness({ native: m => (m.action === "open_app" ? { opened: true } : { count: "0" }) });
  assert.deepEqual(await h.send({ type: "popup_open_app_safari" }), { ok: true });
  assert.deepEqual(h.calls, [{ action: "open_app" }]);
  const iphone = popupHarness({ native: () => ({ error: "unsupported" }) });
  const r = await iphone.send({ type: "popup_open_app_safari" });
  assert.equal(r.ok, false);
  assert.match(r.message, /could not be opened/);
});

test("badge: refreshed at start and after a save, at most every 30 s on tab switches", async () => {
  let count = "1";
  const h = popupHarness({ native: m => (m.action === "pending_count" ? { count } : m.action === "classify" ? { status: "new" } : { stored: true }) });
  h.listeners.startup();
  await settle();
  assert.deepEqual(h.badges, ["1"]);
  h.listeners.activated({ tabId: 1 });
  await settle();
  assert.equal(h.calls.filter(c => c.action === "pending_count").length, 1, "throttled");
  // A save from a page refreshes the badge at once, inside the 30 s.
  count = "2";
  const page = { id: h.id, tab: { id: 4, url: PAGE }, frameId: 0, url: PAGE };
  const g = await h.send({ type: "begin_gesture_browser", origin: ORIGIN, operation_id: "op-save", user_gesture: true }, page);
  assert.equal(g.ok, true);
  const saved = await h.send({ type: "save_browser", origin: ORIGIN, operation_id: "op-save", user_gesture: true,
    gesture_nonce: g.gesture_nonce, username: "alex", password: "pw1" }, page);
  assert.equal(saved.ok, true);
  await settle();
  assert.deepEqual(h.calls.map(c => c.action), ["pending_count", "classify", "save", "pending_count"]);
  assert.deepEqual(h.badges, ["1", "2"]);
  h.clock.now += 31000;
  count = "0";
  h.listeners.activated({ tabId: 1 });
  await settle();
  assert.deepEqual(h.badges, ["1", "2", ""]);
});

test("badge: an older pending_count reply that arrives late never replaces a newer one", async () => {
  const waiting = [];
  const h = popupHarness({ native: m => (m.action === "pending_count" ? new Promise(resolve => waiting.push(resolve)) : {}) });
  const first = h.send({ type: "popup_state_safari" });
  await settle();
  const second = h.send({ type: "popup_state_safari" });
  await settle();
  assert.equal(waiting.length, 2);
  waiting[1]({ count: "1" });
  assert.equal((await second).count, 1);
  assert.deepEqual(h.badges, ["1"]);
  // The first request's answer (the inbox before the save) comes last: the badge keeps the newer count.
  waiting[0]({ count: "5" });
  assert.equal((await first).count, 1, "the popup gets the newer count too");
  assert.deepEqual(h.badges, ["1"]);
  // In order, each reply is shown.
  const third = h.send({ type: "popup_state_safari" });
  await settle();
  waiting[2]({ count: "0" });
  assert.equal((await third).count, 0);
  assert.deepEqual(h.badges, ["1", ""]);
});

test("popup-safari.js lists and fills nothing: it sends only the popup requests", () => {
  const js = readSource("popup-safari.js");
  const html = readSource("popup-safari.html");
  const sent = new Set([...js.matchAll(/send(?:Within)?\("([a-z_]+)"/g)].map(m => m[1]));
  assert.deepEqual([...sent].sort(), ["popup_offer_save_safari", "popup_open_app_safari", "popup_state_safari"]);
  assert.doesNotMatch(js, /sendNativeMessage|password|innerHTML|executeScript/);
  assert.doesNotMatch(html, /<script>(?!<)/, "no inline script (extension CSP)");
  assert.match(js, /state\.can_open === true/, "Open LocalGateKeys only when the native handler can open the app");
  assert.doesNotMatch(js, /getPlatformInfo/, "the native handler decides, not the platform name");
  assert.match(js, /tr\("safari_popup_not_allowed"\)/, "a tab without a url is a site still to allow");
  assert.ok(!loadBuild().safariManifest(JSON.parse(readSource("manifest.json"))).permissions.includes("activeTab"), "no activeTab on Safari");
  const en = require("./i18n-stub.cjs").MESSAGES;
  for (const key of new Set([...html.matchAll(/data-i18n="([^"]+)"/g), ...js.matchAll(/tr\("([a-z_]+)"/g)].map(m => m[1]))) {
    assert.ok(en[key], key);
  }
  assert.equal(en.safari_popup_footer.message, "Your passwords stay in the app. This button never sees them.");
});

// ---- popup-safari.html in jsdom: loading state

function popupPage({ tab = { url: PAGE } } = {}) {
  const { JSDOM } = require("jsdom");
  const dom = new JSDOM(readSource("popup-safari.html"), { runScripts: "outside-only", url: "safari-web-extension://safariext/popup-safari.html" });
  const w = dom.window;
  const timers = [];
  let answer = null;
  w.setTimeout = (f, ms) => { timers.push({ f, ms }); return timers.length; };
  w.clearTimeout = id => { if (timers[id - 1]) timers[id - 1].f = null; };
  w.browser = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage, getUILanguage: () => "en" },
    runtime: { sendMessage: () => new Promise(resolve => { answer = resolve; }) },
    tabs: { query: () => Promise.resolve(tab ? [tab] : []) },
  };
  const ctx = dom.getInternalVMContext();
  vm.runInContext(readSource("api.js"), ctx, { filename: "api.js" });
  vm.runInContext(readSource("popup-safari.js"), ctx, { filename: "popup-safari.js" });
  const $ = id => w.document.getElementById(id);
  return { w, $, timers, reply: r => answer(r), fire: ms => { for (const t of timers) if (t.ms === ms && t.f) { const f = t.f; t.f = null; f(); } } };
}

test("popup: header and fill card at once, Loading… until the background answers", async () => {
  const p = popupPage();
  await settle();
  const en = require("./i18n-stub.cjs").MESSAGES;
  assert.equal(p.$("host").textContent, "example.test");
  assert.equal(p.$("loading").hidden, false);
  assert.equal(p.$("loading").textContent, en.safari_popup_loading.message);
  assert.equal(p.$("offer-row").hidden, true);
  assert.equal(p.$("waiting-row").hidden, true);
  p.reply({ ok: true, count: 2, can_open: true, offer_save: true });
  await settle();
  assert.equal(p.$("loading").hidden, true);
  assert.equal(p.$("offer-row").hidden, false);
  assert.equal(p.$("waiting-row").hidden, false);
  assert.equal(p.$("error").hidden, true);
  assert.equal(p.$("open-app").hidden, false);
  assert.equal(p.w.document.documentElement.classList.contains("ios"), false, "the Mac layout once can_open");
  // A late timer after the reply changes nothing.
  p.fire(30000);
  await settle();
  assert.equal(p.$("error").hidden, true);
});

test("popup: no answer within 30 s shows the failure wording instead of Loading…", async () => {
  const p = popupPage();
  await settle();
  assert.ok(p.timers.some(t => t.ms === 30000), "a 30 s limit");
  p.fire(30000);
  await settle();
  const en = require("./i18n-stub.cjs").MESSAGES;
  assert.equal(p.$("loading").hidden, true);
  assert.equal(p.$("error").hidden, false);
  assert.equal(p.$("error").textContent, en.popup_auto_read_failed.message);
  assert.equal(p.$("offer-row").hidden, true);
  assert.equal(p.$("open-app").hidden, true);
  assert.equal(p.w.document.documentElement.classList.contains("ios"), true);
});

test("popup: a tab without a url is a site still to allow", async () => {
  const p = popupPage({ tab: { id: 3 } });
  await settle();
  assert.match(p.$("host").textContent, /isn't allowed on this site yet/);
  const none = popupPage({ tab: null });
  await settle();
  assert.equal(none.$("host").textContent, "No website in this tab");
});
