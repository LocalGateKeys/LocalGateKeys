/* Safari's save prompt in the panel frame (panel.html), as on Chrome, Edge
 * and Firefox: the Safari manifest declares the frame, background-safari.js
 * relays the frame's requests only for our own panel page in a tab, the
 * frame's Save still needs the content script's gesture nonce, the edited
 * username goes straight to the app's save (no extra classify), and a frame that never reports in
 * falls back to the in-page panel on Safari only. jsdom and a fake
 * `browser`, no network. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const nodeCrypto = require("node:crypto");
const { createPage, EXT } = require("./helpers.cjs");
const { safariManifest } = require(path.join(EXT, "build-safari-extension.cjs"));

const readSource = name => fs.readFileSync(path.join(EXT, name), "utf8");
const plain = value => JSON.parse(JSON.stringify(value));
const PAGE = "https://example.test/login";
const ORIGIN = "https://example.test";
const EXT_ID = "safariext";
const PANEL_URL = `safari-web-extension://${EXT_ID}/panel.html`;
const TOKEN = "0123456789abcdef0123456789abcdef";

// ---- background-safari.js with a fake `browser`

function harness({ native = () => ({ status: "new" }), frames = {}, tabReply = { ok: true } } = {}) {
  const calls = [], relayed = [];
  let listener = null;
  const ns = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: {
      id: EXT_ID,
      getManifest: () => ({ version: "0.4.12" }),
      getURL: p => `safari-web-extension://${EXT_ID}/${p}`,
      onMessage: { addListener: f => { listener = f; } },
      sendMessage: () => Promise.resolve(),
      sendNativeMessage: (app, message) => { calls.push({ ...message }); return Promise.resolve(native(message)); },
    },
    webNavigation: { getFrame: async ({ frameId }) => frames[frameId] },
    tabs: {
      onUpdated: { addListener() {} },
      onRemoved: { addListener() {} },
      sendMessage: (tabId, message, options) => { relayed.push(plain({ tabId, message, options })); return Promise.resolve(tabReply); },
    },
  };
  const context = vm.createContext({ URL, Map, Set, Promise, setTimeout, clearTimeout, Uint8Array, Date,
    crypto: { getRandomValues: a => nodeCrypto.getRandomValues(a) }, browser: ns });
  vm.runInContext(readSource("api.js"), context, { filename: "api.js" });
  vm.runInContext(readSource("background-safari.js"), context, { filename: "background-safari.js" });
  const send = (request, sender) => new Promise(resolve => {
    assert.equal(listener(request, sender, r => resolve(plain(r))), true, "async reply");
  });
  const page = (extra = {}) => ({ id: EXT_ID, tab: { id: 8, url: PAGE }, frameId: 0, url: PAGE, documentId: "doc-page", ...extra });
  const panel = (extra = {}) => ({ id: EXT_ID, tab: { id: 8, url: PAGE }, frameId: 4, url: PANEL_URL, documentId: "doc-panel", ...extra });
  let op = 0;
  const fromPage = (request, sender = page()) => send({ origin: ORIGIN, operation_id: `op-${++op}`, ...request }, sender);
  return { calls, relayed, send, page, panel, fromPage };
}

test("Safari manifest declares panel.html web-accessible for web pages, and ships it", () => {
  const source = JSON.parse(readSource("manifest.json"));
  for (const platform of ["ios", "macos"]) {
    const m = safariManifest(source, platform);
    assert.deepEqual(m.web_accessible_resources, [{ resources: ["panel.html"], matches: ["http://*/*", "https://*/*"] }], platform);
    assert.equal(JSON.stringify(m).includes("use_dynamic_url"), false, "a Chromium-only key Safari does not know");
  }
  for (const dir of ["SafariSave", "SafariMac"]) {
    const res = path.join(EXT, "..", "ios", dir, "Resources");
    const m = JSON.parse(fs.readFileSync(path.join(res, "manifest.json"), "utf8"));
    for (const name of m.web_accessible_resources.flatMap(e => e.resources)) assert.ok(fs.existsSync(path.join(res, name)), `${dir}/${name}`);
  }
});

test("relay: the panel frame's requests go to its parent frame's content script with the frame's id and document", async () => {
  const h = harness({ frames: { 4: { parentFrameId: 0 } }, tabReply: { ok: true, spec: { title: "Save this login?" } } });
  const r = await h.send({ type: "ui_pull", token: TOKEN, origin: "https://evil.test", extra: 1 }, h.panel());
  assert.deepEqual(r, { ok: true, spec: { title: "Save this login?" } });
  assert.deepEqual(h.relayed, [{ tabId: 8, options: { frameId: 0 }, message: { command: "ui", op: "pull", token: TOKEN, frame: { id: 4, document: "doc-panel" } } }]);
  // The edited username goes with the Save click, nothing else from the frame.
  await h.send({ type: "ui_event", token: TOKEN, id: "r0", x: 3, y: 4, detail: 1, visible: null, checks: {}, value: "alice@work", junk: "dropped" }, h.panel());
  assert.deepEqual(h.relayed[1].message, { command: "ui", op: "event", token: TOKEN, id: "r0", x: 3, y: 4, detail: 1, visible: null, checks: {}, value: "alice@work", frame: { id: 4, document: "doc-panel" } });
  // Parent unknown (no webNavigation answer): every frame of the tab is asked; only the token holder answers.
  const all = harness({ frames: {} });
  await all.send({ type: "ui_size", token: TOKEN, height: 120 }, all.panel({ documentId: undefined }));
  assert.equal(all.relayed[0].options, undefined);
  assert.deepEqual(all.relayed[0].message, { command: "ui", op: "size", token: TOKEN, height: 120, frame: { id: 4, document: null } });
  assert.equal(h.calls.length + all.calls.length, 0, "the relay never reaches the native handler");
});

test("relay: only our own panel page, framed in a tab, with a valid token and well-formed fields", async () => {
  const h = harness({ frames: { 4: { parentFrameId: 0 } } });
  const event = { type: "ui_event", token: TOKEN, id: "r1", x: 3, y: 4, detail: 1, visible: null, checks: {} };
  for (const sender of [
    h.panel({ id: "other-extension" }),
    h.panel({ url: "https://evil.test/panel.html" }),
    h.panel({ url: "safari-web-extension://another-extension/panel.html" }),
    h.panel({ url: `safari-web-extension://${EXT_ID}/popup-safari.html` }),
    h.panel({ frameId: 0 }),
    h.panel({ frameId: undefined }),
    h.panel({ tab: undefined }),
    // A content script (the page's own frame) cannot speak for the panel.
    h.page(),
    h.page({ frameId: 4 }),
  ]) assert.equal((await h.send(event, sender)).error, "untrusted_sender", JSON.stringify(sender));
  for (const bad of [
    { token: undefined }, { token: "short" }, { token: TOKEN.toUpperCase() }, { id: "<b>" }, { id: "x".repeat(33) }, { x: "3" }, { y: Infinity },
    { detail: -1 }, { detail: 1.5 }, { visible: "yes" }, { checks: [] }, { checks: { "a b": true } }, { checks: { r1: "true" } },
    { value: "x".repeat(513) }, { value: 7 }, { value: "a\0b" },
  ]) assert.equal((await h.send({ ...event, ...bad }, h.panel())).error, "invalid_request", JSON.stringify(bad));
  assert.equal((await h.send({ type: "ui_size", token: TOKEN, height: 5000 }, h.panel())).error, "invalid_request");
  assert.equal(h.relayed.length, 0, "nothing malformed or foreign reaches the content script");
  // The panel page cannot use the page requests (it is not a web origin).
  assert.equal((await h.send({ type: "save_pending_browser", origin: ORIGIN, operation_id: "x", pending_token: "t", user_gesture: true }, h.panel())).ok, false);
  assert.equal(h.calls.length, 0);
});

test("Save from the framed panel still needs the content script's gesture nonce; the edited username goes straight to the app's save", async () => {
  const h = harness({ native: m => (m.action === "classify" ? { status: "new" } : m.action === "save" ? { stored: true } : {}) });
  const captured = await h.fromPage({ type: "capture_browser", username: "alice", password: "hunter2" });
  const token = captured.pending_token;
  // No gesture: refused, the capture stays.
  for (const extra of [{}, { user_gesture: true }, { user_gesture: true, gesture_nonce: "f".repeat(32) }]) {
    const r = await h.fromPage({ type: "save_pending_browser", pending_token: token, username: "alice@work", ...extra });
    assert.match(r.error, /^(user_gesture_required|gesture_nonce_required|gesture_nonce_invalid)$/, JSON.stringify(extra));
  }
  assert.equal(h.calls.filter(c => c.action === "save").length, 0);
  // A malformed username is refused before anything else.
  assert.equal((await h.fromPage({ type: "save_pending_browser", pending_token: token, username: "" })).error, "invalid_credential");
  assert.equal((await h.fromPage({ type: "save_pending_browser", pending_token: token, username: "x".repeat(513) })).error, "invalid_credential");
  const gesture = async operation_id => (await h.fromPage({ type: "begin_gesture_browser", user_gesture: true, operation_id })).gesture_nonce;
  const nonce = await gesture("op-save");
  const saved = await h.fromPage({ type: "save_pending_browser", pending_token: token, username: "alice@work", user_gesture: true, gesture_nonce: nonce, operation_id: "op-save" });
  assert.equal(saved.ok, true);
  // No classify (no probe) for the edited name: the app's save decides new, exists or full itself.
  assert.deepEqual(h.calls, [
    { action: "classify", origin: ORIGIN, username: "alice", password: "hunter2" },
    { action: "save", origin: ORIGIN, username: "alice@work", password: "hunter2", status: "new" },
  ]);
  // Unchanged username: no second classify, the captured status.
  const t2 = (await h.fromPage({ type: "capture_browser", username: "bob", password: "pw" })).pending_token;
  const before = h.calls.length;
  const n2 = await gesture("op-2");
  assert.equal((await h.fromPage({ type: "save_pending_browser", pending_token: t2, username: "bob", user_gesture: true, gesture_nonce: n2, operation_id: "op-2" })).ok, true);
  assert.deepEqual(h.calls.slice(before), [{ action: "save", origin: ORIGIN, username: "bob", password: "pw", status: "new" }]);
});

test("an edited username: the app's save errors come back as for the captured one; a landing page of another origin cannot rename", async () => {
  for (const [reply, error] of [[{ stored: false, error: "full" }, "full"], [{ stored: false, error: "unavailable" }, "unavailable"], [null, "unavailable"]]) {
    const h = harness({ native: m => (m.action === "classify" ? { status: "new" } : m.action === "save" ? reply : {}) });
    const token = (await h.fromPage({ type: "capture_browser", username: "alice", password: "hunter2" })).pending_token;
    const nonce = (await h.fromPage({ type: "begin_gesture_browser", user_gesture: true, operation_id: "op-1" })).gesture_nonce;
    const r = await h.fromPage({ type: "save_pending_browser", pending_token: token, username: "mallory", user_gesture: true, gesture_nonce: nonce, operation_id: "op-1" });
    assert.equal(r.ok, false);
    assert.equal(r.error, error, JSON.stringify(reply));
    assert.equal(h.calls.filter(c => c.action === "classify").length, 1, "only the capture's classify");
  }
  // A lookalike refusal keeps the capture for the guard's one retry, with the edited name.
  const pair = "0123456789abcdef0123456789abcdef";
  const l = harness({ native: m => (m.action === "classify" ? { status: "new" } : m.action === "save"
    ? (m.lookalike_confirmed === "true" ? { stored: true } : { stored: false, error: "lookalike_site", site: "lookalike", site_reason: "other-suffix", site_matched: "example.com", site_pair: pair }) : {}) });
  const lt = (await l.fromPage({ type: "capture_browser", username: "alice", password: "hunter2" })).pending_token;
  const g1 = (await l.fromPage({ type: "begin_gesture_browser", user_gesture: true, operation_id: "op-a" })).gesture_nonce;
  assert.equal((await l.fromPage({ type: "save_pending_browser", pending_token: lt, username: "alice@work", user_gesture: true, gesture_nonce: g1, operation_id: "op-a" })).error, "lookalike_site");
  const g2 = (await l.fromPage({ type: "begin_gesture_browser", user_gesture: true, operation_id: "op-a" })).gesture_nonce;
  assert.equal((await l.fromPage({ type: "save_pending_browser", pending_token: lt, username: "alice@work", lookalike_confirmed: true, user_gesture: true, gesture_nonce: g2, operation_id: "op-a" })).ok, true);
  assert.deepEqual(l.calls.at(-1), { action: "save", origin: ORIGIN, username: "alice@work", password: "hunter2", status: "new", lookalike_confirmed: "true" });
  assert.equal(l.calls.filter(c => c.action === "classify").length, 1);

  const LOGIN = "https://login.example.test", LANDING = "https://www.example.test";
  const s = harness({ native: m => (m.action === "same_site" ? { same: true } : m.action === "classify" ? { status: "new" } : { stored: true }) });
  const at = origin => s.page({ url: `${origin}/`, tab: { id: 8, url: `${origin}/` } });
  const t = (await s.fromPage({ type: "capture_browser", origin: LOGIN, username: "alice", password: "hunter2" }, at(LOGIN))).pending_token;
  const n = (await s.fromPage({ type: "begin_gesture_browser", origin: LANDING, user_gesture: true, operation_id: "op-l" }, at(LANDING))).gesture_nonce;
  const renamed = await s.fromPage({ type: "save_pending_browser", origin: LANDING, pending_token: t, username: "mallory", user_gesture: true, gesture_nonce: n, operation_id: "op-l" }, at(LANDING));
  assert.equal(renamed.error, "invalid_credential");
  assert.equal(s.calls.filter(c => c.action === "save").length, 0);
  assert.equal((await s.fromPage({ type: "pending_browser", origin: LOGIN }, at(LOGIN))).pending, true, "the capture is still there");
});

// ---- content.js with the Safari manifest (frame declared, Safari background)

const LOGIN_FORM = `<form id="login" action="/session" method="post">
  <input id="user" type="text" name="username" autocomplete="username">
  <input id="pw" type="password" name="password">
  <button id="submit" type="submit">Sign in</button>
</form>`;
function safariResponder({ pendingStatus = "new", notice } = {}) {
  return async request => {
    switch (request.type) {
      case "status": return { ok: true, features: { fill: false } };
      case "agent_status_browser": return { ok: true, agent: false };
      case "classify_site_browser": return { ok: true, unchecked: true };
      case "begin_gesture_browser": return { ok: true, gesture_nonce: "d".repeat(32), gesture_expires_in: 30 };
      case "capture_browser": return { ok: true, stored: true, pending_token: "tok-s" };
      case "pending_browser": return { ok: true, pending: true, pending_token: "tok-s", username: "alice", status: pendingStatus, age_ms: 0, ...(notice ? { notice } : {}) };
      case "save_pending_browser": return { ok: true, notice: "Saved." };
      case "discard_pending_browser": case "clear_pending_browser": case "never_site_browser": return { ok: true };
      default: return { ok: false, error: "unsupported" };
    }
  };
}
async function promptedPage(options = {}, setup = null) {
  const p = createPage({ html: LOGIN_FORM, respond: safariResponder(options), manifest: options.manifest || (m => safariManifest(m, "ios")) });
  if (setup) setup(p);
  p.load();
  await p.tick(6);
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
  await p.tick(8);
  return p;
}
const buttons = p => Array.from(p.panelRoot()?.querySelectorAll("button") || []);
function click(p, label) {
  const b = buttons(p).find(x => x.textContent.includes(label));
  if (!b) throw new Error(`no panel button "${label}" in: ${buttons(p).map(x => x.textContent).join(" | ")}`);
  p.trusted(b, "click", { composed: true }, p.impls.MouseEventImpl);
}
const closePage = p => p.window.dispatchEvent(new p.window.Event("pagehide"));

test("content.js on Safari: the save prompt is drawn in the panel frame with an editable username", async () => {
  const p = await promptedPage();
  const frame = p.panelFrame();
  assert.ok(frame, "the save prompt is a frame");
  assert.match(p.panelText(), /Save this login\?/);
  for (const label of ["Save login", "Not now", "Never on this site"]) assert.ok(buttons(p).some(b => b.textContent.includes(label)), label);
  const input = frame.window.document.querySelector("input");
  assert.equal(input.value, "alice");
  // Not a credential field to Safari AutoFill or other password managers.
  assert.equal(input.getAttribute("type"), "text");
  assert.equal(input.getAttribute("autocomplete"), "off");
  assert.equal(input.name, "lgk-panel-value");
  assert.equal(input.id, "lgk-panel-value");
  assert.doesNotMatch(`${input.name} ${input.id}`, /user|login|email|name=/i);
  for (const [k, v] of [["aria-autocomplete", "none"], ["data-form-type", "other"], ["autocorrect", "off"], ["autocapitalize", "off"], ["data-1p-ignore", ""], ["data-lpignore", "true"], ["data-bwignore", "true"]]) {
    assert.equal(input.getAttribute(k), v, k);
  }
  assert.equal(input.spellcheck, false);
  // The page cannot find the prompt's text or the username field.
  const host = p.shadows.get(p.panelHost());
  assert.doesNotMatch(host.textContent, /Save this login|alice/);
  assert.equal(host.querySelector("input"), null);
  assert.equal(p.sent("site_logins_browser").length, 0, "a new login lists nothing");
  input.value = "alice@work";
  click(p, "Save login");
  await p.tick(10);
  const gestureAt = p.messages.findIndex(m => m.type === "begin_gesture_browser");
  const save = p.sent("save_pending_browser");
  assert.equal(save.length, 1);
  assert.ok(gestureAt >= 0 && gestureAt < p.messages.indexOf(save[0]), "a gesture nonce is asked for first");
  assert.equal(save[0].username, "alice@work");
  assert.equal(save[0].gesture_nonce, "d".repeat(32));
  assert.equal(save[0].user_gesture, true);
  assert.equal(save[0].entry_id, undefined, "Safari never picks a saved login");
  closePage(p);
});

test("content.js on Safari: the prompt is framed even when Safari's getManifest() omits web_accessible_resources", async () => {
  // Seen in real Safari after an app update: the installed manifest declares
  // panel.html, but runtime.getManifest() reports no web_accessible_resources.
  const p = await promptedPage({ manifest: m => { const s = safariManifest(m, "ios"); delete s.web_accessible_resources; return s; } });
  assert.ok(p.panelFrame(), "the save prompt is still a frame");
  assert.match(p.panelText(), /Save this login\?/);
  assert.ok(p.panelFrame().window.document.querySelector("input"), "with the editable username");
  closePage(p);
});

test("content.js on Safari: an untrusted click in the frame saves nothing; Never on this site still works", async () => {
  const p = await promptedPage();
  const save = buttons(p).find(b => b.textContent.includes("Save login"));
  save.click(); // untrusted
  await p.tick(10);
  assert.equal(p.sent("begin_gesture_browser").length, 0);
  assert.equal(p.sent("save_pending_browser").length, 0);
  click(p, "Never on this site");
  await p.tick(10);
  assert.equal(p.sent("never_site_browser").length, 1);
  assert.equal(p.sent("discard_pending_browser").length, 1);
  assert.equal(p.sent("save_pending_browser").length, 0);
  closePage(p);
});

test("content.js on Safari: an existing login asks to update, lists nothing, and a full vault shows its notice without Save", async () => {
  const exists = await promptedPage({ pendingStatus: "exists" });
  assert.ok(exists.panelFrame());
  assert.ok(buttons(exists).some(b => b.textContent === "Save / update"), buttons(exists).map(b => b.textContent).join(" | "));
  assert.ok(exists.panelFrame().window.document.querySelector("input"), "the username is editable");
  assert.equal(exists.panelFrame().window.document.querySelectorAll("[role=radio]").length, 0, "no choose-login list on Safari");
  closePage(exists);
  const notice = "Your free vault is full. Upgrade in LocalGateKeys to save more.";
  const full = await promptedPage({ pendingStatus: "full", notice });
  assert.ok(full.panelFrame());
  assert.ok(full.panelText().includes(notice));
  assert.equal(buttons(full).some(b => b.textContent.includes("Save login")), false);
  assert.equal(full.panelFrame().window.document.querySelector("input"), null, "no username field without Save");
  closePage(full);
});

test("content.js on Safari: a frame that never reports in falls back to the in-page prompt (no blocked notice)", async () => {
  const p = await promptedPage({}, page => {
    // The page's CSP keeps the frame from loading: nothing ever answers for it.
    const original = page.commandListeners.push.bind(page.commandListeners);
    page.commandListeners.push = f => original((message, sender, reply) => (message.command === "ui" ? false : f(message, sender, reply)));
  });
  await p.sleep(3100);
  await p.tick(6);
  assert.equal(p.panelFrame(), null);
  assert.equal(p.shadows.get(p.panelHost()).querySelector("iframe"), null);
  assert.doesNotMatch(p.panelText(), /blocked the LocalGateKeys panel/);
  assert.match(p.panelText(), /Save this login\?/);
  assert.equal(p.shadows.get(p.panelHost()).querySelector("input"), null, "no editable field in the page");
  click(p, "Save login");
  await p.tick(10);
  const save = p.sent("save_pending_browser");
  assert.equal(save.length, 1);
  assert.equal(save[0].username, undefined, "the captured username, unedited");
  assert.equal(save[0].gesture_nonce, "d".repeat(32));
  closePage(p);
});

test("content.js: on a phone-width viewport the prompt narrows to stay on screen; wide viewports keep 320 px", async () => {
  const narrow = await promptedPage({}, p => { p.window.innerWidth = 320; });
  const host = narrow.panelHost();
  assert.ok(narrow.panelFrame());
  assert.equal(host.style.width, "304px");
  assert.equal(host.style.right, "8px");
  closePage(narrow);
  const wide = await promptedPage();
  assert.equal(wide.panelHost().style.width, "320px");
  assert.equal(wide.panelHost().style.right, "18px");
  closePage(wide);
});
