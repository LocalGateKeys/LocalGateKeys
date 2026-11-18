/* Wave 2 (2026-11-15): the click-safe inline menu (each bail-out), the
 * editable save panel (username, which login to update), the change-password
 * update offer, the popup's fill of a chosen login, the passkey hint, and the
 * service worker's site_logins / passkey_hint / save_pending relay. jsdom. */
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
const CHANGE_FORM = `<form id="change" action="/password" method="post">
  <input id="old" type="password" autocomplete="current-password">
  <input id="new1" type="password" autocomplete="new-password">
  <input id="new2" type="password" autocomplete="new-password">
  <button id="go" type="submit">Change</button>
</form>`;
const NONCE = "b".repeat(32);
const ACCOUNTS = [{ entry_id: "e1", username: "alice.secret@example.test", label: "Alice Work" }, { entry_id: "e2", username: "bob.secret@example.test", label: "Bob Private" }];
const LOGINS = [{ entry_id: "e1", title: "Alice Work", username: "alice.secret@example.test" }, { entry_id: "e2", title: "Bob Private", username: "bob.secret@example.test" }];

function responder(state, extra = {}) {
  return async request => {
    if (extra[request.type]) return extra[request.type](request);
    switch (request.type) {
      case "begin_browser": return { ok: true, grant: "g1", session_id: "s1", profile: { name: "Home Vault" }, gesture_nonce: NONCE, gesture_expires_in: 30, choices: ACCOUNTS };
      case "begin_gesture_browser": return { ok: true, gesture_nonce: NONCE, gesture_expires_in: 30 };
      case "get_browser": (state.released ||= []).push(request.entry_id); return { ok: true, credential: { username: ACCOUNTS.find(a => a.entry_id === request.entry_id)?.username || "", password: "s3cret" } };
      case "validate_browser": case "cancel_browser": return { ok: true };
      case "ping": return { ok: true, version: "0.4.12", locked: false };
      case "capture_browser": state.captured = { username: request.username, password: request.password }; return { ok: true, stored: true, pending_token: "tok-1" };
      case "pending_browser": return { ok: true, pending: true, pending_token: "tok-1", username: state.captured?.username ?? "alice", status: state.status || "new", age_ms: 0 };
      case "save_pending_browser": state.savedPending = request; return { ok: true };
      case "discard_pending_browser": state.discarded = request.pending_token; return { ok: true };
      case "clear_pending_browser": state.cleared = (state.cleared || 0) + 1; return { ok: true };
      default: return null;
    }
  };
}
async function loaded(options) { const p = createPage(options); p.load(); await p.tick(); return p; }
const buttons = p => Array.from(p.panelRoot()?.querySelectorAll("button") || []);
function click(p, label) {
  const b = buttons(p).find(x => x.textContent.includes(label));
  if (!b) throw new Error(`no panel button "${label}" in: ${buttons(p).map(x => x.textContent).join(" | ")}`);
  p.trusted(b, "click", { composed: true }, p.impls.MouseEventImpl);
  return b;
}
const clickIcon = p => p.trusted(p.shadows.get(p.fieldIcons()[0]).querySelector("button"), "click", { composed: true }, p.impls.MouseEventImpl);
function pageText(p) {
  const out = [p.document.documentElement.textContent];
  for (const node of p.document.querySelectorAll("*")) { const s = p.shadows.get(node); if (s) out.push(s.textContent); }
  return out.join("\n");
}
async function picker(p) { clickIcon(p); await p.tick(8); assert.ok(p.panelText().includes("Bob Private"), "the picker is shown"); }
const TAMPER = /hid, moved or covered/;

// ---- click-safe inline menu: one test per bail-out

test("click-safe: a page overlay over a corner of the menu cancels the click and points to the toolbar", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM + `<div id="veil"></div>`, respond: responder(state) });
  await picker(p);
  const r = p.panelHost().getBoundingClientRect();
  // The click point itself stays uncovered; only the bottom-right corner is covered.
  const veil = p.document.getElementById("veil");
  p.document.documentElement.appendChild(veil);
  p.setRect(veil, { left: r.right - 20, top: r.bottom - 20, width: 20, height: 20 });
  click(p, "Alice Work");
  await p.tick(8);
  assert.equal(state.released, undefined, "nothing is released");
  assert.match(p.panelText(), TAMPER);
  assert.match(p.panelText(), /browser toolbar/);
});

test("click-safe: a transform on the page root (outside the top layer) cancels the click", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, respond: responder(state) });
  await picker(p);
  p.document.documentElement.style.transform = "scale(1.01)";
  click(p, "Bob Private");
  await p.tick(8);
  assert.equal(state.released, undefined);
  // Without the top layer (this harness) the root's transform also fails the
  // notice, so everything closes; in the top layer the notice stays.
  assert.ok(!p.panelText().includes("Bob Private"), "the menu is gone");
});

test("click-safe: the page fading the menu host closes it at once, before any click", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, respond: responder(state) });
  await picker(p);
  p.panelHost().style.setProperty("opacity", "0.01", "important");
  await p.tick(4);
  assert.match(p.panelText(), TAMPER, "the tampered menu is replaced by the neutral notice");
  assert.ok(!p.panelText().includes("Bob Private"));
});

test("click-safe: pointer-events:none on the host is refused", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, respond: responder(state) });
  await picker(p);
  p.panelHost().style.setProperty("pointer-events", "none", "important");
  await p.tick(4);
  assert.equal(state.released, undefined);
  assert.match(p.panelText(), TAMPER);
});

test("click-safe: the frame reporting itself not visible (IntersectionObserver v2) cancels the click", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, respond: responder(state) });
  await picker(p);
  const frame = p.panelFrame(), token = frame.iframe.name;
  const row = buttons(p).find(b => b.textContent.includes("Bob Private")).dataset.row;
  await new Promise(resolve => p.commandListeners[0]({ command: "ui", op: "event", token, frame: { id: frame.id, document: `doc-${frame.id}` }, id: row, x: 10, y: 10, detail: 1, visible: false, checks: {} }, { id: "testextension" }, resolve));
  await p.tick(6);
  assert.equal(state.released, undefined);
  assert.match(p.panelText(), TAMPER);
});

test("click-safe: an untrusted (script) click in the frame and a click right after the frame appears do nothing", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, respond: responder(state) });
  clickIcon(p);
  p.frameClock.pinned = 0; // the frame's clock stands still: every click is "just shown"
  await p.tick(8);
  const b = buttons(p).find(x => x.textContent.includes("Bob Private"));
  b.click(); // untrusted
  p.trusted(b, "click", { composed: true }, p.impls.MouseEventImpl); // trusted but within the arm delay
  await p.tick(8);
  assert.equal(state.released, undefined);
  p.frameClock.pinned = null;
  p.trusted(b, "click", { composed: true }, p.impls.MouseEventImpl);
  await p.tick(8);
  assert.deepEqual(state.released, ["e2"], "a later trusted click fills");
});

test("click-safe: a click within 500 ms of the panel moving is ignored, later it counts", async () => {
  const state = {};
  const p = await knownSignIn(state, { passkey_hint_browser: () => ({ ok: true, supported: true, has_passkey: false }) });
  assert.match(p.panelText(), /This site supports passkeys/);
  const frame = p.panelFrame();
  // A new size moves the (text-sized) panel.
  await new Promise(resolve => p.commandListeners[0]({ command: "ui", op: "size", token: frame.iframe.name, height: 260, frame: { id: frame.id, document: `doc-${frame.id}` } }, { id: "testextension" }, resolve));
  click(p, "Don't ask for this site");
  await p.tick(8);
  assert.equal(p.storage.passkey_hint_never_origins, undefined, "ignored just after the move");
  assert.doesNotMatch(p.panelText(), TAMPER, "a move alone is not tampering");
  p.clock.now += 600;
  click(p, "Don't ask for this site");
  await p.tick(8);
  assert.deepEqual(JSON.parse(JSON.stringify(p.storage.passkey_hint_never_origins)), ["https://example.test"]);
});

test("L2: save and update prompts keep one host height whatever the login's text or the number of saved logins", async () => {
  const heights = [];
  const sizeTo = async (p, height) => {
    const frame = p.panelFrame();
    await new Promise(resolve => p.commandListeners[0]({ command: "ui", op: "size", token: frame.iframe.name, height, frame: { id: frame.id, document: `doc-${frame.id}` } }, { id: "testextension" }, resolve));
    heights.push(p.panelHost().getBoundingClientRect().height);
  };
  const one = await changeSubmitted({}, { site_logins_browser: () => ({ ok: true, logins: [LOGINS[0]] }) });
  await sizeTo(one, 140);
  await sizeTo(one, 190); // a longer login name wraps to more lines
  const many = await changeSubmitted({}, { site_logins_browser: () => ({ ok: true, logins: LOGINS }) });
  await sizeTo(many, 300);
  const saveNew = await savePanel({ status: "new" });
  await sizeTo(saveNew, 210);
  const saveExists = await savePanel({ status: "exists" }, { site_logins_browser: () => ({ ok: true, logins: LOGINS }) });
  await sizeTo(saveExists, 330);
  assert.deepEqual(heights, [320, 320, 320, 320, 320]);
});

test("click-safe: 'always use the popup' on this site: no inline icons; the popup's fill still works", async () => {
  const state = {};
  const p = createPage({ html: LOGIN_FORM, respond: responder(state) });
  p.storage.popup_only_origins = ["https://example.test"];
  p.load(); await p.tick(6);
  assert.equal(p.fieldIcons().length, 0, "no icon on a popup-only site");
  const r = await p.command("fill_current", { entry_id: "e2" });
  assert.equal(r.ok, true);
  await p.tick(8);
  assert.deepEqual(state.released, ["e2"]);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
});

// ---- the popup's fill of a chosen login

test("popup fill: fill_current with a listed entry_id fills that login; an unknown one releases nothing", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, respond: responder(state) });
  await p.command("fill_current", { entry_id: "e1" });
  await p.tick(8);
  assert.deepEqual(state.released, ["e1"]);
  assert.equal(p.document.getElementById("user").value, "alice.secret@example.test");
  const q = await loaded({ html: LOGIN_FORM, respond: responder({}) });
  await q.command("fill_current", { entry_id: "nope" });
  await q.tick(8);
  assert.equal(q.sent("get_browser").length, 0);
  assert.equal((await q.command("fill_current", { entry_id: 7 })).ok, false, "a non-string id is refused");
});

// ---- the save panel

async function savePanel(state, extra = {}) {
  const p = await loaded({ html: LOGIN_FORM, respond: responder(state, extra) });
  const d = p.document;
  d.getElementById("user").value = "alice"; d.getElementById("pw").value = "pw";
  p.trusted(d.getElementById("login"), "submit", { submitter: d.getElementById("submit") }, p.impls.SubmitEventImpl);
  await p.tick(4);
  p.clock.now += 1000;
  d.getElementById("login").remove();
  await p.command("check_pending_save");
  await p.sleep(140); await p.tick(8);
  return p;
}

test("save panel: the username is editable in the frame and an edit is sent with save_pending_browser", async () => {
  const state = {};
  const p = await savePanel(state);
  const input = p.panelRoot().querySelector("label.field input");
  assert.equal(input.value, "alice");
  assert.ok(!pageText(p).includes("alice"), "the username is not in page DOM");
  input.value = "  alice@example.test ";
  click(p, "Save login");
  await p.tick(8);
  assert.equal(state.savedPending.username, "alice@example.test");
  assert.equal(state.savedPending.entry_id, undefined);
});

test("save panel: an unchanged username is not resent", async () => {
  const state = {};
  const p = await savePanel(state);
  click(p, "Save login");
  await p.tick(8);
  assert.equal(state.savedPending.pending_token, "tok-1");
  assert.equal("username" in state.savedPending, false);
});

test("save panel: an existing login on a site with several logins offers the choice; it stays in the frame", async () => {
  const state = { status: "exists" };
  const p = await savePanel(state, { site_logins_browser: () => ({ ok: true, logins: LOGINS }) });
  assert.match(p.panelText(), /Which saved login/);
  for (const s of ["Alice Work", "Bob Private"]) { assert.ok(p.panelText().includes(s)); assert.ok(!pageText(p).includes(s), `${s} not in page DOM`); }
  const radios = buttons(p).filter(b => b.getAttribute("role") === "radio");
  assert.equal(radios.length, 2);
  p.trusted(radios[0], "click", { composed: true }, p.impls.MouseEventImpl);
  p.trusted(radios[1], "click", { composed: true }, p.impls.MouseEventImpl);
  assert.equal(radios[0].getAttribute("aria-checked"), "false", "one choice at a time");
  assert.equal(radios[1].getAttribute("aria-checked"), "true");
  click(p, "Save / update");
  await p.tick(8);
  assert.equal(state.savedPending.entry_id, "e2");
});

test("save panel: an older app without site_logins_browser shows no chooser and still saves", async () => {
  const state = { status: "exists" };
  const p = await savePanel(state);
  assert.equal(buttons(p).filter(b => b.getAttribute("role") === "radio").length, 0);
  click(p, "Save / update");
  await p.tick(8);
  assert.equal(state.savedPending.pending_token, "tok-1");
});

// ---- change-password forms without a username field

async function changeSubmitted(state, extra, { html = CHANGE_FORM, after = d => d.getElementById("change").remove() } = {}) {
  const p = await loaded({ html, respond: responder(state, extra) });
  const d = p.document;
  d.getElementById("old").value = "old-pw"; d.getElementById("new1").value = "N3w-pw!"; d.getElementById("new2").value = "N3w-pw!";
  p.trusted(d.getElementById("change"), "submit", { submitter: d.getElementById("go") }, p.impls.SubmitEventImpl);
  await p.tick(6);
  assert.deepEqual(state.captured, { username: "", password: "N3w-pw!" });
  p.clock.now += 1000;
  after(d, p);
  await p.command("check_pending_save");
  await p.sleep(140); await p.tick(8);
  return p;
}

// Finding M1: the update offer is judged by the submitted form only, and a
// failure reading waits instead of dropping the capture.
const EMAIL_FORM = `<form id="email" action="/email" method="post"><input id="mail" type="email" name="email" required><button type="submit">Change email</button></form>`;
const REQUIRED_CHANGE_FORM = CHANGE_FORM.replace(/<input id="(old|new1|new2)" /g, '<input id="$1" required ');

test("M1: an empty required field in another form of the settings page does not hide the update offer", async () => {
  const state = {};
  const p = await changeSubmitted(state, { site_logins_browser: () => ({ ok: true, logins: [LOGINS[0]] }) }, { html: EMAIL_FORM + CHANGE_FORM });
  assert.equal(p.document.getElementById("mail").matches(":invalid"), true, "the other form's field is :invalid");
  assert.match(p.panelText(), /Update password for Alice Work/);
  assert.equal(state.cleared, undefined);
});

test("M1: an SPA that clears its required fields after the change still gets the offer", async () => {
  const state = {};
  const p = await changeSubmitted(state, { site_logins_browser: () => ({ ok: true, logins: [LOGINS[0]] }) }, {
    html: REQUIRED_CHANGE_FORM,
    after: (d, page) => { for (const id of ["old", "new1", "new2"]) d.getElementById(id).value = ""; page.window.history.pushState({}, "", "/settings/done"); },
  });
  assert.match(p.panelText(), /Update password for Alice Work/);
});

test("M1: a change the site visibly refused gets no offer, and the capture is kept for later checks", async () => {
  const state = {};
  const p = await changeSubmitted(state, { site_logins_browser: () => ({ ok: true, logins: [LOGINS[0]] }) }, {
    html: CHANGE_FORM + `<div id="err" role="alert"></div>`,
    after: d => { d.getElementById("err").textContent = "Incorrect password"; },
  });
  p.clock.now += 6000; // long past the "uncertain" point
  await p.command("check_pending_save");
  await p.sleep(1500); await p.tick(8);
  assert.equal(p.panelVisible(), false);
  assert.equal(p.sent("site_logins_browser").length, 0);
  assert.equal(state.cleared, undefined, "a failure reading waits, it does not drop the capture");
});

test("live recheck: after 'Not now' a pending check already in flight does not draw the offer again", async () => {
  const state = {};
  // The app still answers pending (the discard has not reached it yet).
  const p = await changeSubmitted(state, { site_logins_browser: () => ({ ok: true, logins: [LOGINS[0]] }) });
  assert.match(p.panelText(), /Update password for Alice Work/);
  p.clock.now += 600;
  click(p, "Not now");
  await p.tick(6);
  assert.equal(p.panelVisible(), false);
  await p.command("check_pending_save");
  await p.sleep(1500); await p.tick(8);
  assert.equal(p.panelVisible(), false, "not redrawn");
  assert.equal(p.sent("site_logins_browser").length, 1);
});

test("M1: the submitted form's own field marked invalid by the site is a failure", async () => {
  const state = {};
  const p = await changeSubmitted(state, { site_logins_browser: () => ({ ok: true, logins: [LOGINS[0]] }) }, {
    after: d => { d.getElementById("old").setAttribute("aria-invalid", "true"); },
  });
  p.clock.now += 6000;
  await p.command("check_pending_save");
  await p.sleep(1500); await p.tick(8);
  assert.equal(p.panelVisible(), false);
  assert.equal(p.sent("site_logins_browser").length, 0);
});

test("change password: one saved login is offered by name, saved only on the click", async () => {
  const state = {};
  const p = await changeSubmitted(state, { site_logins_browser: () => ({ ok: true, logins: [LOGINS[0]] }) });
  assert.match(p.panelText(), /Update a saved password/);
  assert.ok(!pageText(p).includes("Alice Work"));
  assert.equal(state.savedPending, undefined, "nothing saved without a click");
  click(p, "Update password for Alice Work");
  await p.tick(8);
  assert.equal(state.savedPending.entry_id, "e1");
  assert.equal("username" in state.savedPending, false, "only entry_id: the app keeps the login's own username");
});

test("change password: several logins are listed; the chosen one is updated", async () => {
  const state = {};
  const p = await changeSubmitted(state, { site_logins_browser: () => ({ ok: true, logins: LOGINS }) });
  click(p, "Bob Private");
  await p.tick(8);
  assert.equal(state.savedPending.entry_id, "e2");
});

test("change password: no list (older app, locked) shows the neutral note; nothing is guessed or saved", async () => {
  const state = {};
  const p = await changeSubmitted(state, {});
  assert.match(p.panelText(), /no saved login it can update/);
  assert.equal(state.cleared, undefined, "the capture is answered like an offer, not dropped early");
  click(p, "Close");
  await p.tick(6);
  assert.equal(p.panelVisible(), false);
  assert.equal(state.discarded, "tok-1");
  assert.equal(state.savedPending, undefined);
});

// Finding L2 (rest): what a page script can read about the host must not
// depend on how many logins are saved (0, 1, several) or on the app being
// unable to list them. The frame's own reported height varies with its text.
async function hostSnapshot(logins, frameHeight) {
  const state = {};
  const p = await changeSubmitted(state, { site_logins_browser: () => (logins ? { ok: true, logins } : { ok: false, error: "locked" }) });
  const frame = p.panelFrame();
  assert.ok(frame, "a panel frame is drawn");
  await new Promise(resolve => p.commandListeners[0]({ command: "ui", op: "size", token: frame.iframe.name, height: frameHeight, frame: { id: frame.id, document: `doc-${frame.id}` } }, { id: "testextension" }, resolve));
  await p.tick(4);
  const host = p.panelHost();
  const rect = host.getBoundingClientRect();
  const cs = p.window.getComputedStyle(host);
  return {
    connected: host.isConnected, parent: host.parentNode === p.document.documentElement, last: p.document.documentElement.lastElementChild === host,
    // the data attribute name is random per page load
    attrs: Array.from(host.attributes).map(a => a.name === "style" ? a.name : `${a.name.startsWith("data-") ? "data-*" : a.name}=${a.value}`).sort().join(" "),
    style: host.getAttribute("style").replace(/(top|left|right|bottom): [^;]+;/g, ""), // position is the same corner, checked by size only
    width: rect.width, height: rect.height, display: cs.display, zIndex: cs.zIndex, focused: p.document.activeElement === host,
    children: host.children.length, sentAfter: ["clear_pending_browser", "passkey_hint_browser"].map(t => p.sent(t).length).join(","),
    text: p.panelText(),
  };
}

test("L2: a password-only submit draws the same host for 0, 1 or several saved logins and for a locked vault", async () => {
  const none = await hostSnapshot([], 120);
  const one = await hostSnapshot([LOGINS[0]], 170);
  const many = await hostSnapshot(LOGINS, 300);
  const locked = await hostSnapshot(null, 110);
  assert.match(none.text, /no saved login it can update/);
  assert.match(one.text, /Update password for Alice Work/);
  assert.match(many.text, /Bob Private/);
  for (const s of [none, one, many, locked]) delete s.text;
  assert.equal(none.height, 320);
  assert.deepEqual(one, none);
  assert.deepEqual(many, none);
  assert.deepEqual(locked, none);
  assert.equal(none.sentAfter, "0,0", "no early clear, no passkey note on this path");
});

test("L2: the neutral note answers like an offer: 'Close' is final for this capture, it is not drawn again", async () => {
  const state = {};
  const p = await changeSubmitted(state, { site_logins_browser: () => ({ ok: true, logins: [] }) });
  p.clock.now += 600;
  click(p, "Close");
  await p.tick(6);
  await p.command("check_pending_save");
  await p.sleep(1500); await p.tick(8);
  assert.equal(p.panelVisible(), false);
  assert.equal(state.discarded, "tok-1");
  assert.equal(p.sent("site_logins_browser").length, 1);
});

// ---- passkey hint

async function knownSignIn(state, extra) {
  const p = await loaded({ html: LOGIN_FORM, respond: responder(state, { capture_browser: () => ({ ok: true, stored: false }), ...extra }) });
  const d = p.document;
  d.getElementById("user").value = "alice"; d.getElementById("pw").value = "pw";
  p.trusted(d.getElementById("login"), "submit", { submitter: d.getElementById("submit") }, p.impls.SubmitEventImpl);
  await p.tick(4);
  d.getElementById("login").remove();
  await p.sleep(1600); await p.tick(8);
  return p;
}

test("passkey hint: after a sign-in on a site that supports passkeys (no passkey saved), a one-time note; 'Don't ask' is stored", async () => {
  const state = {};
  const p = await knownSignIn(state, { passkey_hint_browser: () => ({ ok: true, supported: true, has_passkey: false }) });
  assert.match(p.panelText(), /This site supports passkeys/);
  assert.equal(p.sent("passkey_hint_browser").length, 1);
  click(p, "Don't ask for this site");
  await p.tick(6);
  assert.deepEqual(JSON.parse(JSON.stringify(p.storage.passkey_hint_never_origins)), ["https://example.test"]);
  assert.equal(p.panelVisible(), false);
});

test("passkey hint: nothing when the app lacks the command, the vault has a passkey, or the site said no before", async () => {
  const old = await knownSignIn({}, {});
  assert.equal(old.panelVisible(), false, "older app: unsupported_request");
  const has = await knownSignIn({}, { passkey_hint_browser: () => ({ ok: true, supported: true, has_passkey: true }) });
  assert.equal(has.panelVisible(), false);
  const p = createPage({ html: LOGIN_FORM, respond: responder({}, { capture_browser: () => ({ ok: true, stored: false }), passkey_hint_browser: () => ({ ok: true, supported: true, has_passkey: false }) }) });
  p.storage.passkey_hint_never_origins = ["https://example.test"];
  p.load(); await p.tick();
  const d = p.document;
  d.getElementById("user").value = "alice"; d.getElementById("pw").value = "pw";
  p.trusted(d.getElementById("login"), "submit", { submitter: d.getElementById("submit") }, p.impls.SubmitEventImpl);
  await p.tick(4); d.getElementById("login").remove();
  await p.sleep(1600); await p.tick(8);
  assert.equal(p.sent("passkey_hint_browser").length, 0);
});

// ---- service worker

function worker(native, { frameId = 0, tabUrl = "https://example.test/login", clock = null, session = null } = {}) {
  let listener; const calls = []; const id = "testextension"; const url = tabUrl; const origin = new URL(url).origin;
  const frames = { 0: { documentId: "doc-top", url, documentLifecycle: "active", errorOccurred: false, parentFrameId: -1 },
    3: { documentId: "doc-3", url, documentLifecycle: "active", errorOccurred: false, parentFrameId: 0 } };
  const chrome = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: { id, getManifest: () => ({ version: "0.4.12", permissions: [] }), getURL: p => `chrome-extension://${id}/${p}`, onMessage: { addListener: f => listener = f },
      sendNativeMessage: (host, req) => { calls.push(req); return Promise.resolve(typeof native === "function" ? native(req) : { ...native }); } },
    webNavigation: { getFrame: async ({ frameId: f }) => frames[f], onDOMContentLoaded: { addListener() {} }, onCompleted: { addListener() {} }, onHistoryStateUpdated: { addListener() {} } },
    tabs: { get: async () => ({ active: true, discarded: false }), query: async () => [{ id: 8, url }], sendMessage: () => Promise.resolve() },
    ...(session ? { storage: { session } } : {}),
  };
  const context = vm.createContext({ chrome, URL, Set, Map, Promise, setTimeout, clearTimeout, Uint8Array, btoa, crypto: globalThis.crypto, fetch: async () => ({ ok: false }),
    ...(clock ? { Date: class extends Date { static now() { return clock.now; } } } : {}) });
  vm.runInContext(fs.readFileSync(path.join(EXT, "api.js"), "utf8"), context);
  vm.runInContext(fs.readFileSync(path.join(EXT, "background.js"), "utf8"), context);
  const send = (req, sender = { id, tab: { id: 8 }, frameId, documentId: frameId ? "doc-3" : "doc-top", url }) =>
    new Promise(resolve => listener({ origin, operation_id: "op-1", ...req }, sender, r => resolve(JSON.parse(JSON.stringify(r)))));
  const popup = req => send(req, { id, url: `chrome-extension://${id}/popup.html` });
  return { calls, send, popup, frames };
}

test("worker: site_logins_browser is cleaned (no secrets, at most 20) and refused from subframes", async () => {
  const many = Array.from({ length: 25 }, (_, i) => ({ entry_id: `e${i}`, title: `T${i}`, username: `u${i}`, password: "leak" }));
  const w = worker(req => req.action === "site_logins_browser" ? { ok: true, logins: [{ entry_id: 7 }, ...many] } : { ok: true, stored: true });
  await w.send({ type: "capture_browser", username: "", password: "pw" }); // the ticket (finding W-L2)
  const r = await w.send({ type: "site_logins_browser" });
  assert.equal(r.logins.length, 19, "bad rows dropped, capped at 20 before cleaning");
  assert.deepEqual(Object.keys(r.logins[0]).sort(), ["entry_id", "title", "username"]);
  assert.ok(!JSON.stringify(r).includes("leak"));
  assert.equal(w.calls[1].action, "site_logins_browser");
  assert.equal(w.calls[1].origin, "https://example.test");
  const sub = worker({ ok: true, logins: [] }, { frameId: 3 });
  assert.equal((await sub.send({ type: "site_logins_browser" })).ok, false);
  assert.equal(sub.calls.length, 0);
  const old = worker(req => req.action === "capture_browser" ? { ok: true, stored: false } : { ok: false, error: "unknown_command" });
  await old.send({ type: "capture_browser", username: "a", password: "pw" });
  assert.deepEqual(await old.send({ type: "site_logins_browser" }), { ok: false, error: "unsupported" });
});

test("worker: the popup's site_logins uses the active tab's origin, never one from the request", async () => {
  const w = worker({ ok: true, logins: [LOGINS[0]] });
  const r = await w.popup({ type: "site_logins", origin: "https://evil.test" });
  assert.equal(r.ok, true);
  assert.equal(r.origin, "https://example.test");
  assert.equal(w.calls[0].origin, "https://example.test");
  assert.deepEqual(r.logins, [LOGINS[0]]);
});

test("worker: save_pending_browser forwards an edited username and entry_id; passkey_hint is reduced to two flags", async () => {
  const w = worker(req => req.action === "passkey_hint_browser" ? { ok: true, supported: true, has_passkey: false, url: "x" } : { ok: true });
  await w.send({ type: "save_pending_browser", pending_token: "t", username: "bob", entry_id: "e2" });
  const save = w.calls.find(c => c.action === "save_pending_browser");
  assert.equal(save.username, "bob"); assert.equal(save.entry_id, "e2");
  assert.equal((await w.send({ type: "save_pending_browser", pending_token: "t", username: "x".repeat(513) })).error, "invalid_credential");
  assert.deepEqual(await w.send({ type: "passkey_hint_browser" }), { ok: true, supported: true, has_passkey: false }, "the ok save is the ticket");
  const old = worker(req => req.action === "capture_browser" ? { ok: true, stored: false } : { ok: false, error: "unknown_command" });
  await old.send({ type: "capture_browser", username: "a", password: "pw" });
  assert.deepEqual(await old.send({ type: "passkey_hint_browser" }), { ok: false, error: "unsupported" });
});

// ---- 2026-11-15 recheck: password-only captures are update-only (the app's
// "update_only" status, entry_required / entry_not_for_site), finding W-L2
// (no site probes without a just-captured submit) and W-L15 (popup-only sites).

test("change password: the app's update_only status offers the update; only entry_id is sent", async () => {
  const state = {};
  const p = await changeSubmitted(state, {
    pending_browser: () => ({ ok: true, pending: true, pending_token: "tok-1", username: "", status: "update_only", age_ms: 0 }),
    site_logins_browser: () => ({ ok: true, logins: [LOGINS[1]] }),
  });
  assert.match(p.panelText(), /Update password for Bob Private/);
  assert.doesNotMatch(p.panelText(), /Save login/, "never offered as a new login");
  click(p, "Update password for Bob Private");
  await p.tick(8);
  assert.equal(state.savedPending.entry_id, "e2");
  assert.equal(state.savedPending.pending_token, "tok-1");
  assert.equal("username" in state.savedPending, false);
});

for (const [code, text] of [["entry_required", /Choose which saved login gets this password/], ["entry_not_for_site", /not saved for this site, so its password was not changed/]]) {
  test(`change password: the app's ${code} answer is shown as a readable message`, async () => {
    const state = {};
    const p = await changeSubmitted(state, {
      site_logins_browser: () => ({ ok: true, logins: [LOGINS[0]] }),
      save_pending_browser: request => { state.savedPending = request; return { ok: false, error: code }; },
    });
    click(p, "Update password for Alice Work");
    await p.tick(8);
    assert.match(p.panelText(), text);
    assert.doesNotMatch(pageText(p), text, "the message is drawn in the extension frame");
  });
}

test("change password: the site's logins are listed once, not again on every pending check", async () => {
  const state = {};
  const p = await changeSubmitted(state, { site_logins_browser: () => ({ ok: true, logins: LOGINS }) });
  assert.match(p.panelText(), /Bob Private/);
  await p.command("check_pending_save");
  await p.sleep(1500); await p.tick(8);
  assert.equal(p.sent("site_logins_browser").length, 1);
});

test("change password: a password-only capture handed to another origin of the site is not offered", async () => {
  const state = {};
  const p = await changeSubmitted(state, {
    pending_browser: () => ({ ok: true, pending: true, pending_token: "tok-1", status: "update_only", handoff: true, origin: "https://accounts.example.test", age_ms: 0 }),
    site_logins_browser: () => ({ ok: true, logins: LOGINS }),
  });
  assert.equal(p.panelVisible(), false);
  assert.equal(p.sent("site_logins_browser").length, 0, "no list for another origin's capture");
  assert.equal(state.savedPending, undefined);
});

test("W-L2: a password-only submit without transient activation (script requestSubmit) is not captured; a named one is", async () => {
  const state = {};
  const p = await loaded({ html: CHANGE_FORM + LOGIN_FORM, respond: responder(state) });
  Object.defineProperty(p.window.navigator, "userActivation", { value: { hasBeenActive: true, isActive: false }, configurable: true });
  const d = p.document;
  d.getElementById("old").value = "old"; d.getElementById("new1").value = "N3w-pw!"; d.getElementById("new2").value = "N3w-pw!";
  p.trusted(d.getElementById("change"), "submit", { submitter: d.getElementById("go") }, p.impls.SubmitEventImpl);
  await p.tick(6);
  assert.equal(p.sent("capture_browser").length, 0, "password-only: nothing kept");
  d.getElementById("user").value = "alice"; d.getElementById("pw").value = "pw";
  p.trusted(d.getElementById("login"), "submit", { submitter: d.getElementById("submit") }, p.impls.SubmitEventImpl);
  await p.tick(6);
  assert.equal(p.sent("capture_browser").length, 1, "a named sign-in is still captured");
  p.window.navigator.userActivation.isActive = true;
  p.clock.now += 2000;
  d.getElementById("new1").value = "N3w-pw!2"; d.getElementById("new2").value = "N3w-pw!2";
  p.trusted(d.getElementById("change"), "submit", { submitter: d.getElementById("go") }, p.impls.SubmitEventImpl);
  await p.tick(6);
  assert.equal(p.sent("capture_browser").length, 2, "with the user's own submit it is captured");
});

test("W-L15: on a popup-only site no capture is kept and no save panel or passkey note is drawn", async () => {
  const state = {};
  const p = createPage({ html: LOGIN_FORM, respond: responder(state, { passkey_hint_browser: () => ({ ok: true, supported: true, has_passkey: false }) }) });
  p.storage.popup_only_origins = ["https://example.test"];
  p.load(); await p.tick(6);
  const d = p.document;
  d.getElementById("user").value = "alice"; d.getElementById("pw").value = "pw";
  p.trusted(d.getElementById("login"), "submit", { submitter: d.getElementById("submit") }, p.impls.SubmitEventImpl);
  await p.tick(4);
  p.clock.now += 1000;
  d.getElementById("login").remove();
  await p.command("check_pending_save");
  await p.sleep(1600); await p.tick(8);
  assert.equal(p.sent("capture_browser").length, 0);
  assert.equal(p.sent("pending_browser").length, 0);
  assert.equal(p.sent("passkey_hint_browser").length, 0);
  assert.equal(p.panelVisible(), false);
});

test("W-L15: turning popup-only on while a save prompt is waiting closes it and stops the checks", async () => {
  const state = { status: "new" };
  const p = await savePanel(state);
  assert.match(p.panelText(), /Save this login/);
  assert.ok(p.storageListeners.length > 0);
  for (const f of p.storageListeners) f({ popup_only_origins: { newValue: ["https://example.test"] } }, "local");
  await p.tick(4);
  assert.equal(p.panelVisible(), false);
  const before = p.sent("pending_browser").length;
  await p.command("check_pending_save");
  await p.sleep(1500); await p.tick(8);
  assert.equal(p.sent("pending_browser").length, before, "no automatic prompt on a popup-only site");
});

test("worker W-L2: site_logins_browser / passkey_hint_browser need a ticket from this tab's top-frame capture or save", async () => {
  const native = req => req.action === "site_logins_browser" ? { ok: true, logins: [LOGINS[0]] }
    : req.action === "passkey_hint_browser" ? { ok: true, supported: true, has_passkey: false } : { ok: true, stored: true };
  const w = worker(native);
  assert.deepEqual(await w.send({ type: "site_logins_browser" }), { ok: false, error: "user_gesture_required" });
  assert.deepEqual(await w.send({ type: "passkey_hint_browser" }), { ok: false, error: "user_gesture_required" });
  assert.equal(w.calls.length, 0, "no native request without a ticket");
  await w.send({ type: "capture_browser", username: "", password: "pw" });
  for (let i = 0; i < 4; i++) assert.equal((await w.send({ type: i % 2 ? "passkey_hint_browser" : "site_logins_browser" })).ok, true);
  assert.equal((await w.send({ type: "site_logins_browser" })).error, "user_gesture_required", "four requests per ticket");
  // A failed capture (rate limited) grants nothing.
  const limited = worker(req => req.action === "capture_browser" ? { ok: false, error: "rate_limited" } : native(req));
  await limited.send({ type: "capture_browser", username: "a", password: "pw" });
  assert.equal((await limited.send({ type: "site_logins_browser" })).ok, false);
  // The popup's own list needs no ticket.
  const popup = worker(native);
  assert.equal((await popup.popup({ type: "site_logins" })).ok, true);
});

test("worker W-L2: a ticket expires after two minutes and a subframe capture grants none", async () => {
  const native = req => req.action === "site_logins_browser" ? { ok: true, logins: [] } : { ok: true, stored: true };
  const clock = { now: 1_700_000_000_000 };
  const w = worker(native, { clock });
  await w.send({ type: "capture_browser", username: "", password: "pw" });
  clock.now += 119000;
  assert.equal((await w.send({ type: "site_logins_browser" })).ok, true, "still valid just under two minutes");
  clock.now += 2000;
  assert.equal((await w.send({ type: "site_logins_browser" })).error, "user_gesture_required");
  const sub = worker(native, { frameId: 3 });
  await sub.send({ type: "capture_browser", username: "", password: "pw" });
  const top = { id: "testextension", tab: { id: 8 }, frameId: 0, documentId: "doc-top", url: "https://example.test/login" };
  assert.equal((await sub.send({ type: "site_logins_browser" }, top)).error, "user_gesture_required");
});

test("final review L6: a step-one username survives a worker restart (storage.session), once, same origin, 5 minutes", async () => {
  const data = new Map();
  const session = {
    async set(o) { for (const [k, v] of Object.entries(o)) data.set(k, JSON.parse(JSON.stringify(v))); },
    async get(k) { return data.has(k) ? { [k]: data.get(k) } : {}; },
    async remove(k) { data.delete(k); },
  };
  const clock = { now: 1_700_000_000_000 };
  const first = worker({ ok: true }, { session, clock });
  assert.equal((await first.send({ type: "step_username_browser", username: "bob@example.test" })).ok, true);
  const restarted = worker({ ok: true }, { session, clock }); // a fresh worker: its memory is empty
  assert.deepEqual(await restarted.send({ type: "recall_username_browser" }), { ok: true, username: "bob@example.test" });
  assert.deepEqual(await restarted.send({ type: "recall_username_browser" }), { ok: true, username: "" }, "handed out once");
  await first.send({ type: "step_username_browser", username: "late@example.test" });
  clock.now += 300001;
  assert.deepEqual(await worker({ ok: true }, { session, clock }).send({ type: "recall_username_browser" }), { ok: true, username: "" }, "expired");
  assert.equal(data.size, 0);
});

test("M2: a top-frame capture whose page navigated before the app answered still grants the ticket, for the capture's origin only", async () => {
  const native = req => {
    // A classic POST form: the next document commits while the app answers.
    if (req.action === "capture_browser") { w.frames[0].documentId = "doc-next"; return { ok: true, stored: true }; }
    return req.action === "site_logins_browser" ? { ok: true, logins: [LOGINS[0]] } : { ok: false, error: "rate_limited" };
  };
  const w = worker(native);
  const r = await w.send({ type: "capture_browser", username: "", password: "pw" });
  assert.equal(r.error, "destination_changed", "the late reply itself is still dropped");
  const next = { id: "testextension", tab: { id: 8 }, frameId: 0, documentId: "doc-next", url: "https://example.test/password/done" };
  assert.equal((await w.send({ type: "site_logins_browser" }, next)).ok, true, "the next page of the same origin may list");
  // Moved to another origin: that origin has no ticket.
  const other = worker(req => { if (req.action === "capture_browser") { other.frames[0].documentId = "doc-x"; other.frames[0].url = "https://other.test/"; } return { ok: true, stored: true, logins: [] }; });
  await other.send({ type: "capture_browser", username: "", password: "pw" });
  other.frames[0].url = "https://other.test/";
  const elsewhere = { id: "testextension", tab: { id: 8 }, frameId: 0, documentId: "doc-x", url: "https://other.test/" };
  assert.equal((await other.send({ type: "site_logins_browser", origin: "https://other.test" }, elsewhere)).ok, false);
  assert.equal(other.calls.filter(c => c.action === "site_logins_browser").length, 0, "no list for the origin the tab moved to");
  // An app refusal grants nothing, navigation or not.
  const refused = worker(req => { refused.frames[0].documentId = "doc-y"; return { ok: false, error: "rate_limited" }; });
  await refused.send({ type: "capture_browser", username: "", password: "pw" });
  const y = { id: "testextension", tab: { id: 8 }, frameId: 0, documentId: "doc-y", url: "https://example.test/login" };
  assert.equal((await refused.send({ type: "site_logins_browser" }, y)).error, "user_gesture_required");
});

test("W-L2: a trusted Enter in a password-only form counts as the user's own submit", async () => {
  const state = {};
  const p = await loaded({ html: CHANGE_FORM, respond: responder(state) });
  Object.defineProperty(p.window.navigator, "userActivation", { value: { hasBeenActive: true, isActive: false }, configurable: true });
  const d = p.document;
  d.getElementById("old").value = "old"; d.getElementById("new1").value = "N3w-pw!"; d.getElementById("new2").value = "N3w-pw!";
  p.trusted(d.getElementById("new2"), "keydown", { key: "Enter", bubbles: true }, p.impls.KeyboardEventImpl);
  await p.tick(6);
  assert.deepEqual(state.captured, { username: "", password: "N3w-pw!" });
});
