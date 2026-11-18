/* The panel frame (panel.html): vault text never enters DOM the page can read
 * or search, the frame's token is bound to one frame, clicks need a trusted,
 * armed, visible panel, and without the frame the in-page panel shows only
 * neutral placeholders. Plus the service worker's relay. jsdom, no network. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const { createPage, EXT } = require("./helpers.cjs");

const LOGIN_FORM = `<form id="login" action="/session" method="post">
  <input id="user" type="text" name="username" autocomplete="username">
  <input id="pw" type="password" name="password">
  <button id="submit" type="submit">Sign in</button>
</form>`;
const CARD_FORM = `<form id="pay" action="/charge" method="post">
  <input id="name" type="text" autocomplete="cc-name"><input id="number" type="text" autocomplete="cc-number">
  <input id="exp" type="text" autocomplete="cc-exp"><input id="cvc" type="text" autocomplete="cc-csc">
</form>`;
const IDENTITY_FORM = `<form action="/profile" method="post"><input id="email" type="email" autocomplete="email"><input id="given" autocomplete="given-name"></form>`;

// Vault text the page must never find.
const SECRETS = ["alice.secret@example.test", "Alice Work", "bob.secret@example.test", "Bob Private", "Home Vault", "Personal Visa", "Work Amex", "4242", "0005", "My Identity", "www.amazon.com"];
const ACCOUNTS = [{ entry_id: "e1", username: "alice.secret@example.test", label: "Alice Work" }, { entry_id: "e2", username: "bob.secret@example.test", label: "Bob Private" }];
const NONCE = "a".repeat(32);

function cardChoice(overrides) {
  const fields = {};
  for (const token of ["cc-name", "cc-number", "cc-exp", "cc-csc"]) fields[token] = { label: token, protected: token === "cc-number" || token === "cc-csc", present: true };
  return { entry_id: "card-1", title: "Personal Visa", favorite: false, revision: 1, brand: "Visa", last4: "4242", fields, ...overrides };
}
function responder(extra = {}) {
  const state = { released: [] };
  const respond = async request => {
    if (extra[request.type]) return extra[request.type](request);
    switch (request.type) {
      case "begin_browser": return { ok: true, grant: "g1", session_id: "s1", profile: { name: "Home Vault" }, gesture_nonce: NONCE, gesture_expires_in: 30, choices: ACCOUNTS };
      case "begin_gesture_browser": return { ok: true, gesture_nonce: NONCE, gesture_expires_in: 30 };
      case "get_browser": state.released.push(request.entry_id); return { ok: true, credential: { username: ACCOUNTS.find(a => a.entry_id === request.entry_id)?.username || "", password: "s3cret" } };
      case "begin_card_browser": return { ok: true, card_protocol: 1, origin: request.origin, session_id: "s1", profile: { name: "Home Vault" }, gesture_nonce: NONCE, gesture_expires_in: 30,
        choices: [cardChoice(), cardChoice({ entry_id: "card-2", title: "Work Amex", brand: "Amex", last4: "0005" })] };
      case "begin_identity_browser": return { ok: true, session_id: "s1", profile: { name: "Home Vault" },
        choices: [{ entry_id: "i1", revision: 1, title: "My Identity", fields: ["email", "given_name"] }, { entry_id: "i2", revision: 1, title: "Other Identity", fields: ["email"] }] };
      case "validate_browser": return { ok: true };
      case "ping": return { ok: true, version: "0.4.12", locked: false };
      case "cancel_browser": case "cancel_card_browser": case "cancel_identity_browser": return { ok: true };
      default: return null;
    }
  };
  return { state, respond };
}
async function loaded(options) { const p = createPage(options); p.load(); await p.tick(); return p; }
const closePage = p => p.window.dispatchEvent(new p.window.Event("pagehide"));

// Everything the page can read or search: its DOM text and attributes,
// including every shadow root (window.find() searches closed ones too).
// Frame documents are cross-origin to the page and are left out.
function pageVisible(p) {
  const out = [];
  const walk = root => {
    for (const node of root.querySelectorAll("*")) {
      for (const attr of node.attributes) out.push(attr.value);
      const shadow = p.shadows.get(node);
      if (shadow) { out.push(shadow.textContent); walk(shadow); }
    }
  };
  out.push(p.document.documentElement.textContent);
  walk(p.document);
  return out.join("\n");
}
function assertNoSecrets(p, where) {
  const text = pageVisible(p);
  for (const secret of SECRETS) assert.ok(!text.includes(secret), `${where}: the page can find "${secret}"`);
}
const rowButtons = p => Array.from(p.panelRoot()?.querySelectorAll("button") || []);
function click(p, label) {
  const b = rowButtons(p).find(x => x.textContent.includes(label));
  if (!b) throw new Error(`no panel button "${label}" in: ${rowButtons(p).map(x => x.textContent).join(" | ")}`);
  p.trusted(b, "click", { composed: true }, p.impls.MouseEventImpl);
  return b;
}
const iconButton = (p, host) => p.shadows.get(host).querySelector("button");
const clickIcon = (p, host) => p.trusted(iconButton(p, host), "click", { composed: true }, p.impls.MouseEventImpl);
// What the content script hands the relay for this page's command listener.
const ui = (p, message) => new Promise(resolve => {
  const kept = p.commandListeners[0]({ command: "ui", ...message }, { id: "testextension" }, resolve);
  if (kept !== true) setImmediate(() => resolve(undefined));
});

test("account picker: names are drawn in the frame, the page finds none of them", async () => {
  const { respond } = responder();
  const p = await loaded({ html: LOGIN_FORM, respond });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  const frame = p.panelFrame();
  assert.ok(frame, "the panel is a frame");
  for (const s of ["Alice Work", "alice.secret@example.test", "Bob Private", "Home Vault"]) assert.ok(p.panelText().includes(s), s);
  assertNoSecrets(p, "account picker");
  const iframe = p.shadows.get(p.panelHost()).querySelector("iframe");
  assert.equal(iframe.getAttribute("src"), "chrome-extension://testextension/panel.html", "no data in the URL");
  assert.match(iframe.name, /^[0-9a-f]{32}$/);
  assert.equal(frame.window.name, "", "the frame clears its token from the window name");
  assert.deepEqual(frame.sent.map(m => m.type).slice(0, 2), ["ui_pull", "ui_size"]);
  click(p, "Bob Private");
  await p.tick(8);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  closePage(p);
});

test("Firefox reports web-accessible resources as \"/panel.html\": the panel still uses the frame", async () => {
  // Firefox's runtime.getManifest() gives "/panel.html"; the check took only "panel.html", so every
  // Firefox panel fell back to the in-page placeholders ("#1", "Card 1").
  const { respond } = responder();
  const manifest = m => ({ ...m, web_accessible_resources: m.web_accessible_resources.map(e => ({ ...e, resources: e.resources.map(r => "/" + r) })) });
  const p = await loaded({ html: LOGIN_FORM, respond, manifest });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.ok(p.panelFrame(), "the panel is a frame");
  assert.ok(p.panelText().includes("Alice Work"));
  assertNoSecrets(p, "account picker (Firefox manifest)");
  closePage(p);
});

test("card and identity pickers and the lookalike guard keep their text in the frame", async () => {
  const { respond } = responder();
  const card = await loaded({ html: CARD_FORM, respond });
  await card.command("fill_card");
  await card.tick(8);
  assert.match(card.panelText(), /Amex •••• 0005/);
  assertNoSecrets(card, "card picker");
  click(card, "Work Amex");
  await card.tick(8);
  assert.match(card.panelText(), /Work Amex/);
  assertNoSecrets(card, "card fields");
  closePage(card);

  const identity = await loaded({ html: IDENTITY_FORM, respond });
  await identity.command("fill_identity");
  await identity.tick(8);
  assert.match(identity.panelText(), /My Identity/);
  assertNoSecrets(identity, "identity picker");
  closePage(identity);

  const verdict = { ok: true, kind: "lookalike", reason: "other-suffix", matched: "www.amazon.com", pair: "0123456789abcdef0123456789abcdef" };
  const guard = await loaded({ html: LOGIN_FORM, url: "https://www.amazon.example/login", respond: responder({ classify_site_browser: () => verdict }).respond });
  guard.trusted(guard.document.getElementById("pw"), "focusin", { bubbles: true });
  await guard.tick(6);
  guard.document.getElementById("user").value = "alice";
  guard.document.getElementById("pw").value = "hunter2";
  guard.trusted(guard.document.getElementById("login"), "submit", { submitter: guard.document.getElementById("submit") }, guard.impls.SubmitEventImpl);
  await guard.tick(8);
  assert.ok(guard.panelText().includes("www.amazon.com"), guard.panelText());
  assertNoSecrets(guard, "lookalike guard");
  closePage(guard);
});

test("without the frame (Safari, or a frame that never loads) the in-page panel shows placeholders only", async () => {
  const { respond } = responder();
  const p = await loaded({ html: LOGIN_FORM, respond, frame: false });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.equal(p.panelFrame(), null);
  assert.equal(p.shadows.get(p.panelHost()).querySelector("iframe"), null);
  // Rows are masks only: no row number, no match hint the page could count or read.
  const rows = rowButtons(p).filter(b => b.classList.contains("account"));
  assert.equal(rows.length, 2);
  for (const row of rows) assert.doesNotMatch(row.textContent, /#\d|whole domain|path/i);
  assertNoSecrets(p, "in-page account picker");
  // Still usable: the second row fills the second account.
  p.trusted(rows[1], "click", { composed: true }, p.impls.MouseEventImpl);
  await p.tick(8);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  closePage(p);

  const card = await loaded({ html: CARD_FORM, respond, frame: false });
  await card.command("fill_card");
  await card.tick(8);
  assert.doesNotMatch(card.panelText(), /Card \d/);
  assert.equal(rowButtons(card).filter(b => b.classList.contains("account")).length, 2);
  assertNoSecrets(card, "in-page card picker");
  closePage(card);
});

test("a frame that never reports in (page removed or blocked it) cancels: no in-page picker, use the toolbar", async () => {
  const { respond } = responder();
  const p = await loaded({ html: LOGIN_FORM, respond });
  // The page keeps the frame from loading: nothing ever answers for it.
  const listener = p.commandListeners[0];
  p.commandListeners[0] = (message, sender, reply) => (message.command === "ui" ? false : listener(message, sender, reply));
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.equal(p.panelText(), "", "nothing drawn yet");
  await p.sleep(3100);
  assert.equal(p.shadows.get(p.panelHost()).querySelector("iframe"), null);
  assert.match(p.panelText(), /blocked the LocalGateKeys panel/);
  assert.equal(rowButtons(p).filter(b => b.classList.contains("account")).length, 0, "no saved-item rows in the page");
  assertNoSecrets(p, "timed-out frame");
  // The next panel tries the frame again; the document is not switched to the in-page renderer.
  p.commandListeners[0] = listener;
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.ok(p.panelFrame(), "the frame is used again");
  closePage(p);
});

test("a page that removes the panel host gets the toolbar notice, not the in-page picker", async () => {
  const { respond } = responder();
  const p = await loaded({ html: LOGIN_FORM, respond });
  const listener = p.commandListeners[0];
  p.commandListeners[0] = (message, sender, reply) => (message.command === "ui" ? false : listener(message, sender, reply));
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  p.panelHost()?.remove();
  await p.sleep(3100);
  assert.match(p.panelText(), /blocked the LocalGateKeys panel/);
  assert.equal(rowButtons(p).filter(b => b.classList.contains("account")).length, 0);
  assertNoSecrets(p, "removed host");
  closePage(p);
});

test("the token is bound to the first frame that presents it; others get nothing", async () => {
  const { respond, state } = responder();
  const p = await loaded({ html: LOGIN_FORM, respond });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  const iframe = p.shadows.get(p.panelHost()).querySelector("iframe");
  const token = iframe.name;
  // Wrong token: no reply at all.
  assert.equal(await ui(p, { op: "pull", token: "f".repeat(32), frame: { id: 7, document: "doc-7" } }), undefined);
  // The right token from another frame or document: refused, no spec.
  assert.deepEqual({ ...(await ui(p, { op: "pull", token, frame: { id: 99, document: "doc-x" } })) }, { ok: false });
  assert.deepEqual({ ...(await ui(p, { op: "pull", token, frame: { id: 7, document: "doc-other" } })) }, { ok: false });
  await ui(p, { op: "event", token, frame: { id: 99, document: "doc-x" }, id: "r1", x: 0, y: 0, detail: 0, visible: null, checks: {} });
  await p.tick(6);
  assert.deepEqual(state.released, [], "a foreign frame cannot pick a row");
  // The bound frame still works.
  const reply = await ui(p, { op: "pull", token, frame: { id: 7, document: "doc-7" } });
  assert.equal(reply.ok, true);
  assert.ok(reply.spec.rows.some(r => r.label.includes("Alice Work")));
  closePage(p);
});

test("frame clicks: untrusted, too early, or on a covered panel do nothing", async () => {
  const { respond, state } = responder();
  const p = await loaded({ html: LOGIN_FORM, respond });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  const frame = p.panelFrame();
  const row = rowButtons(p).find(b => b.textContent.includes("Alice Work"));
  // A synthetic click (not from the user).
  row.dispatchEvent(new frame.window.MouseEvent("click", { bubbles: true }));
  await p.tick(6);
  assert.equal(frame.sent.filter(m => m.type === "ui_event").length, 0);
  // A click within the arm delay after the panel was drawn.
  p.frameClock.pinned = p.frameClock.now;
  click(p, "Bob Private");
  await p.tick(6);
  p.frameClock.pinned = null;
  assert.equal(frame.sent.filter(m => m.type === "ui_event").length, 0, "not armed yet");
  assert.deepEqual(state.released, []);
  // The frame reports itself covered (IntersectionObserver v2): tampering.
  await ui(p, { op: "event", token: p.shadows.get(p.panelHost()).querySelector("iframe").name, frame: { id: frame.id, document: `doc-${frame.id}` },
    id: rowButtons(p).find(b => b.textContent.includes("Bob Private")).dataset.row, x: 10, y: 10, detail: 1, visible: false, checks: {} });
  await p.tick(8);
  assert.deepEqual(state.released, []);
  assert.match(p.panelText(), /LocalGateKeys/);
  assert.ok(!p.panelText().includes("Alice Work"), "the picker is gone");
  closePage(p);
});

// IntersectionObserver v2 as Chromium behaves: an observer's first reading
// is taken when it starts observing, and a frame that was still hidden then
// (the host is placed only after the frame reports its size) can stay "not
// visible" for good. panel.js must take a fresh reading once it is placed.
function visibilityObserver(placed) {
  return fw => {
    fw.IntersectionObserverEntry = class { get isVisible() { return false; } };
    fw.IntersectionObserver = class {
      constructor(callback) { this.callback = callback; }
      observe(target) { const isVisible = placed(); setImmediate(() => this.callback([{ target, isVisible }])); }
      disconnect() {}
    };
  };
}
test("frame clicks: a panel that was hidden when its frame loaded counts as visible once placed", async () => {
  const { respond, state } = responder();
  let p = null;
  const placed = () => !!p && p.panelHost()?.style.getPropertyValue("display") === "block";
  p = await loaded({ html: LOGIN_FORM, respond, frameSetup: visibilityObserver(() => placed()) });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(12);
  click(p, "Bob Private");
  await p.tick(8);
  assert.deepEqual(state.released, ["e2"], "a real click on a visible panel fills");
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  closePage(p);
});

test("frame clicks: the host must be intact at the click point", async () => {
  const { respond, state } = responder();
  const p = await loaded({ html: LOGIN_FORM, respond });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  // The page covers the panel with its own element.
  const cover = p.document.createElement("div");
  p.document.documentElement.append(cover);
  const r = p.panelHost().getBoundingClientRect();
  p.setRect(cover, { left: r.left, top: r.top, width: r.width, height: r.height });
  click(p, "Bob Private");
  await p.tick(8);
  assert.deepEqual(state.released, [], "a covered panel releases nothing");
  closePage(p);
});

test("panel.js listens for no page messages and reads no URL parameters", () => {
  const src = fs.readFileSync(path.join(EXT, "panel.js"), "utf8");
  for (const re of [/addEventListener\(\s*["']message["']/, /postMessage\s*\(/, /onMessage/, /location\.(search|hash)/, /URLSearchParams/, /innerHTML/]) assert.ok(!re.test(src), String(re));
  assert.match(src, /e\.isTrusted/);
});

// ---- The service worker's relay.
function worker({ frames = {}, reply = { ok: true } } = {}) {
  const source = fs.readFileSync(path.join(EXT, "background.js"), "utf8");
  const shim = fs.readFileSync(path.join(EXT, "api.js"), "utf8");
  let listener; const relayed = [];
  const ns = {
    runtime: {
      id: "testextension", getManifest: () => ({ version: "0.4.12", permissions: [] }), getURL: p => `chrome-extension://testextension/${p}`,
      onMessage: { addListener: f => listener = f }, sendNativeMessage: () => Promise.resolve({ ok: true }), sendMessage: () => Promise.resolve(),
    },
    webNavigation: { getFrame: async ({ frameId }) => frames[frameId], onDOMContentLoaded: { addListener() {} }, onCompleted: { addListener() {} }, onHistoryStateUpdated: { addListener() {} } },
    tabs: { get: async () => ({ active: true }), sendMessage: (tabId, message, options) => { relayed.push({ tabId, message, options }); return Promise.resolve(reply); } },
  };
  const context = vm.createContext({ URL, Set, Promise, setTimeout, clearTimeout, Uint8Array, btoa, chrome: ns, fetch: async () => ({ ok: false }) });
  vm.runInContext(shim, context); vm.runInContext(source, context);
  const send = (request, sender) => new Promise(resolve => listener(request, sender, resolve));
  return { send, relayed };
}
const PANEL_URL = "chrome-extension://3f2a9c7d1e/panel.html"; // dynamic host (use_dynamic_url)
const TOKEN = "0123456789abcdef0123456789abcdef";
const panelSender = (extra = {}) => ({ id: "testextension", tab: { id: 8 }, frameId: 4, documentId: "doc-panel", url: PANEL_URL, ...extra });

test("relay: the panel's requests go to its parent frame with the browser's frame id and document", async () => {
  const w = worker({ frames: { 4: { parentFrameId: 2 } }, reply: { ok: true, spec: { title: "x" } } });
  const r = await w.send({ type: "ui_pull", token: TOKEN, origin: "https://evil.test", extra: 1 }, panelSender());
  assert.deepEqual(JSON.parse(JSON.stringify(r)), { ok: true, spec: { title: "x" } });
  assert.equal(w.relayed.length, 1);
  assert.deepEqual(JSON.parse(JSON.stringify(w.relayed[0])), { tabId: 8, options: { frameId: 2 },
    message: { command: "ui", op: "pull", token: TOKEN, frame: { id: 4, document: "doc-panel" } } });
  // Without a known parent the message goes to the tab's frames; only the
  // content script holding the token answers.
  const all = worker({ frames: {} });
  await all.send({ type: "ui_size", token: TOKEN, height: 120 }, panelSender({ documentId: undefined }));
  assert.equal(all.relayed[0].options, undefined);
  assert.deepEqual(JSON.parse(JSON.stringify(all.relayed[0].message)), { command: "ui", op: "size", token: TOKEN, height: 120, frame: { id: 4, document: null } });
});

test("relay: only our own panel page, inside a tab frame, with well-formed fields", async () => {
  const w = worker({ frames: { 4: { parentFrameId: 0 } } });
  const event = { type: "ui_event", token: TOKEN, id: "r1", x: 3, y: 4, detail: 1, visible: true, checks: { r2: false }, value: "Gen3rated!pass" };
  for (const sender of [
    panelSender({ url: "https://evil.test/panel.html" }),
    panelSender({ url: "chrome-extension://3f2a9c7d1e/popup.html" }),
    panelSender({ frameId: 0 }),
    panelSender({ tab: undefined }),
  ]) assert.equal((await w.send(event, sender)).error, "untrusted_sender", sender.url);
  for (const bad of [
    { token: "short" }, { token: TOKEN.toUpperCase() }, { id: "<b>" }, { id: "x".repeat(33) }, { x: "3" }, { y: Infinity }, { detail: -1 }, { detail: 1.5 },
    { visible: "yes" }, { checks: [] }, { checks: { "a b": true } }, { checks: { r1: "true" } }, { value: "x".repeat(513) }, { value: 7 },
  ]) assert.equal((await w.send({ ...event, ...bad }, panelSender())).error, "invalid_request", JSON.stringify(bad));
  assert.equal((await w.send({ type: "ui_size", token: TOKEN, height: 5000 }, panelSender())).error, "invalid_request");
  assert.equal(w.relayed.length, 0, "nothing malformed reaches the page's content script");
  await w.send({ ...event, junk: "dropped" }, panelSender());
  assert.deepEqual(JSON.parse(JSON.stringify(w.relayed[0].message)), { command: "ui", op: "event", token: TOKEN, id: "r1", x: 3, y: 4, detail: 1, visible: true,
    checks: { r2: false }, value: "Gen3rated!pass", frame: { id: 4, document: "doc-panel" } });
});
