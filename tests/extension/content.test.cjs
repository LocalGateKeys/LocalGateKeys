"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createPage } = require("./helpers.cjs");

const LOGIN_FORM = `<form id="login" action="/session" method="post">
  <input id="user" type="text" name="username" autocomplete="username">
  <input id="pw" type="password" name="password">
  <button id="submit" type="submit">Sign in</button>
</form>`;

// Broker protocol 2 (hardened): begin_* mint a 30 s single-use gesture nonce;
// get_browser must present it; ping is {ok, version, locked} only.
const NONCE_A = "a".repeat(32), NONCE_B = "b".repeat(32);
function fillResponder({ signIn = false, credential = { username: "alice", password: "s3cret" }, choices = null, state = {} } = {}) {
  state.minted = 0; state.releases = [];
  return async request => {
    switch (request.type) {
      case "begin_browser": return { ok: true, grant: "grant-1", session_id: "s1", profile: { name: "Home" }, gesture_nonce: NONCE_A, gesture_expires_in: 30,
        choices: choices || [{ entry_id: "e1", username: credential.username }] };
      case "begin_gesture_browser": state.minted++; return { ok: true, gesture_nonce: NONCE_B, gesture_expires_in: 30 };
      case "get_browser":
        state.releases.push(request);
        if (state.rejectNonces && state.releases.length <= state.rejectNonces) return { ok: false, error: "gesture_nonce_invalid" };
        return { ok: true, credential: { ...credential }, sign_in: signIn };
      case "validate_browser": return { ok: true };
      case "ping": return { ok: true, version: "0.3.2", locked: false };
      case "cancel_browser": return { ok: true };
      default: return null;
    }
  };
}
const TWO_ACCOUNTS = [{ entry_id: "e1", username: "alice", label: "Alice" }, { entry_id: "e2", username: "bob", label: "Bob" }];
// Buttons live in the closed shadow root of the panel; a trusted click is fired the way the browser would.
function panelButtons(p) { const root = p.shadows.get(p.panelHost()); return root ? Array.from(root.querySelectorAll("button")) : []; }
function clickPanelButton(p, text) {
  const button = panelButtons(p).find(b => b.textContent.includes(text));
  if (!button) throw new Error(`no panel button containing "${text}" in: ${panelButtons(p).map(b => b.textContent).join(" | ")}`);
  p.trusted(button, "click", { composed: true }, p.impls.MouseEventImpl);
}

async function loaded(options) {
  const p = createPage(options);
  p.load();
  await p.tick();
  return p;
}

test("fill icons appear on current-password fields, including inside open shadow roots", async () => {
  const p = createPage({ html: `${LOGIN_FORM}<div id="host"></div><form><input id="np" type="password" autocomplete="new-password"></form>` });
  p.openShadow(p.document.getElementById("host"), `<form action="/s" method="post"><input id="shadow-pw" type="password"></form>`);
  p.load();
  await p.tick();
  assert.equal(p.fieldIcons().length, 2, "document field + shadow field; new-password excluded");
  assert.equal(p.otpIcons().length, 0);
});

test("fill_current fills username and password from the native reply without submitting", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: fillResponder() });
  const { document: d } = p;
  let submitted = 0;
  d.getElementById("login").addEventListener("submit", () => submitted++);
  const reply = await p.command("fill_current");
  assert.equal(reply.ok, true);
  await p.tick(8);
  assert.equal(d.getElementById("user").value, "alice");
  assert.equal(d.getElementById("pw").value, "s3cret");
  assert.equal(submitted, 0);
  assert.deepEqual(p.messages.slice(0, 3).map(m => m.type), ["begin_browser", "get_browser", "validate_browser"]);
  for (const m of p.messages) {
    assert.equal(m.origin, "https://example.test");
    assert.match(m.operation_id, /^[0-9a-f-]{36}$/);
  }
  assert.equal(p.sent("get_browser")[0].username_only, false);
  assert.equal(p.sent("submit_browser").length, 0);
  p.window.dispatchEvent(new p.window.Event("pagehide")); // stops the status interval
});

test("the gesture nonce minted by begin_browser is forwarded once with get_browser; no second mint is needed", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, respond: fillResponder({ state }) });
  await p.command("fill_current");
  await p.tick(8);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  const release = p.sent("get_browser")[0];
  assert.equal(release.gesture_nonce, NONCE_A);
  assert.equal(release.user_gesture, true, "legacy user_gesture flag kept for compatibility");
  assert.equal(release.operation_id, p.sent("begin_browser")[0].operation_id, "nonce is bound to the begin operation's context");
  assert.equal(release.session_id, undefined);
  assert.equal(state.minted, 0);
  assert.equal(p.sent("begin_gesture_browser").length, 0);
  p.window.dispatchEvent(new p.window.Event("pagehide"));
});

test("a ping without session_id or browser_enabled keeps the account picker open; only locked:true resets it", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS, state }) });
  await p.command("fill_current");
  await p.tick(6);
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /Choose an account/);
  await p.sleep(1300); // one status-poll interval
  await p.tick(4);
  assert.ok(p.sent("ping").length >= 1, "the page polled ping while the picker was open");
  assert.equal(p.panelVisible(), true, "{ok, version, locked:false} must not reset the page");
  assert.match(p.panelText(), /Choose an account/);
  assert.equal(p.sent("cancel_browser").length, 0);
  clickPanelButton(p, "Bob");
  await p.tick(8);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  assert.equal(p.sent("get_browser")[0].entry_id, "e2");
  assert.equal(p.sent("get_browser")[0].gesture_nonce, NONCE_A, "picked within 30 s: the begin nonce is still used");
  p.window.dispatchEvent(new p.window.Event("pagehide"));
});

test("ping reporting locked:true cancels the open fill", async () => {
  let locked = false;
  const inner = fillResponder({ choices: TWO_ACCOUNTS });
  const p = await loaded({ html: LOGIN_FORM, respond: async r => r.type === "ping" ? { ok: true, version: "0.3.2", locked } : inner(r) });
  await p.command("fill_current");
  await p.tick(6);
  assert.equal(p.panelVisible(), true);
  locked = true;
  await p.sleep(1300);
  await p.tick(4);
  assert.equal(p.panelVisible(), false);
  assert.equal(p.sent("cancel_browser").length, 1);
});

test("expired nonce path: a later trusted click re-mints via begin_gesture_browser and never presents the stale nonce", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS, state }) });
  await p.command("fill_current");
  await p.tick(6);
  const beginOp = p.sent("begin_browser")[0].operation_id;
  p.clock.now += 31_000; // the 30 s nonce aged out while the picker was open
  clickPanelButton(p, "Alice");
  await p.tick(10);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  const mint = p.sent("begin_gesture_browser");
  assert.equal(mint.length, 1);
  assert.equal(mint[0].user_gesture, true);
  assert.equal(mint[0].operation_id, beginOp, "re-mint uses the same operation so the nonce binds to the same context");
  const release = p.sent("get_browser");
  assert.equal(release.length, 1, "the stale nonce was not sent first");
  assert.equal(release[0].gesture_nonce, NONCE_B);
  assert.equal(release[0].operation_id, beginOp);
  p.window.dispatchEvent(new p.window.Event("pagehide"));
});

test("gesture_nonce_invalid is retried once with a fresh nonce while the click is in flight", async () => {
  const state = { rejectNonces: 1 };
  const p = await loaded({ html: LOGIN_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS, state }) });
  await p.command("fill_current");
  await p.tick(6);
  clickPanelButton(p, "Alice");
  await p.tick(10);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  assert.deepEqual(state.releases.map(r => r.gesture_nonce), [NONCE_A, NONCE_B]);
  assert.equal(state.minted, 1);
  p.window.dispatchEvent(new p.window.Event("pagehide"));
});

test("a second gesture_nonce_invalid is not retried again: the user is told to click again", async () => {
  const state = { rejectNonces: 99 };
  const p = await loaded({ html: LOGIN_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS, state }) });
  await p.command("fill_current");
  await p.tick(6);
  clickPanelButton(p, "Alice");
  await p.tick(10);
  assert.equal(p.document.getElementById("pw").value, "");
  assert.equal(state.releases.length, 2, "exactly one retry");
  assert.equal(state.minted, 1);
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /Click again/);
});

test("a gesture_nonce_invalid that arrives after the gesture window is not retried: no silent re-mint from a stale click", async () => {
  // The broker answered late (e.g. a long unlock prompt). By then the click
  // that started the release is older than the in-flight window, so the page
  // must not mint a new nonce on its own; it shows the click-again message.
  const state = {};
  const inner = fillResponder({ choices: TWO_ACCOUNTS, state });
  const p = await loaded({ html: LOGIN_FORM, respond: async r => {
    if (r.type === "get_browser") { state.releases.push(r); p.clock.now += 6_000; return { ok: false, error: "gesture_nonce_invalid" }; }
    return inner(r);
  } });
  await p.command("fill_current");
  await p.tick(6);
  clickPanelButton(p, "Alice");
  await p.tick(10);
  assert.equal(p.document.getElementById("pw").value, "");
  assert.equal(state.releases.length, 1, "no retry");
  assert.equal(state.releases[0].gesture_nonce, NONCE_A);
  assert.equal(p.sent("begin_gesture_browser").length, 0);
  assert.match(p.panelText(), /Click again/);
});

test("begin_browser and get_browser carry the page url without its fragment; the account picker labels non-exact matches", async () => {
  const choices = [
    { entry_id: "e1", username: "alice", label: "Alice", match: "exact_origin" },
    { entry_id: "e2", username: "bob", label: "Bob", match: "host" },
    { entry_id: "e3", username: "carol", label: "Carol", match: "starts_with" },
  ];
  const p = await loaded({ html: LOGIN_FORM, url: "https://example.test/account/login?next=%2Fhome#form", respond: fillResponder({ choices }) });
  await p.command("fill_current");
  await p.tick(6);
  assert.equal(p.sent("begin_browser")[0].url, "https://example.test/account/login?next=%2Fhome");
  const text = p.panelText();
  assert.match(text, /Alice/);
  assert.doesNotMatch(text.slice(text.indexOf("Alice"), text.indexOf("Bob")), /matches/, "exact-origin rows carry no hint");
  assert.match(text, /Bob[^]*matches host/);
  assert.match(text, /Carol[^]*matches URL prefix/);
  clickPanelButton(p, "Carol");
  await p.tick(8);
  assert.equal(p.sent("get_browser")[0].url, "https://example.test/account/login?next=%2Fhome");
  assert.equal(p.sent("get_browser")[0].entry_id, "e3");
  p.window.dispatchEvent(new p.window.Event("pagehide"));
});

test("fill_current refuses a form that posts to another origin before any native call", async () => {
  const p = await loaded({ html: `<form action="https://evil.test/login" method="post"><input id="pw" type="password"></form>`, respond: fillResponder() });
  await p.command("fill_current");
  await p.tick(4);
  assert.equal(p.sent("begin_browser").length, 0);
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /another origin/);
  assert.equal(p.document.getElementById("pw").value, "");
});

test("username-only first step: email field gets an icon and is filled with username_only", async () => {
  const p = await loaded({ html: `<form id="step1" action="/next" method="post"><input id="email" type="email" autocomplete="username"><button type="submit">Next</button></form>`, respond: fillResponder() });
  assert.equal(p.fieldIcons().length, 1);
  const reply = await p.command("fill_current");
  assert.equal(reply.ok, true);
  await p.tick(8);
  assert.equal(p.sent("get_browser")[0].username_only, true);
  assert.equal(p.document.getElementById("email").value, "alice");
  p.window.dispatchEvent(new p.window.Event("pagehide"));
});

test("generate_new fills matching new-password fields with one strong value and refuses cross-origin forms", async () => {
  const p = await loaded({ html: `<form id="signup" action="/register" method="post"><input id="a" type="password" autocomplete="new-password"><input id="b" type="password" autocomplete="new-password"></form>` });
  const reply = await p.command("generate_new");
  assert.equal(reply.ok, true);
  const a = p.document.getElementById("a").value, b = p.document.getElementById("b").value;
  assert.equal(a.length, 24);
  assert.equal(a, b);
  assert.match(a, /^[abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%\-_]+$/);
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /Password generated/);

  const q = await loaded({ html: `<form action="https://evil.test/register" method="post"><input id="a" type="password" autocomplete="new-password"></form>` });
  const refused = await q.command("generate_new");
  assert.equal(refused.ok, false);
  assert.equal(q.document.getElementById("a").value, "");
});

// ---- save-outcome heuristics. A trusted submit captures the attempt; the
// save prompt appears only when the login surface disappeared, the URL
// changed, or (after a grace period) the outcome is uncertain, and never
// while a failure message is visible. Saving itself is gesture-gated: the
// Save click mints a nonce (begin_gesture_browser) for the same operation.
const NONCE_SAVE = "c".repeat(32);
function saveResponder(state = {}) {
  return async request => {
    switch (request.type) {
      case "begin_gesture_browser": state.minted = (state.minted || 0) + 1; return { ok: true, gesture_nonce: NONCE_SAVE, gesture_expires_in: 30 };
      case "check_browser": state.checked = { username: request.username, password: request.password }; return { ok: true, locked: false, match: false, status: "new", prompt: true };
      case "save_browser": state.savedDirect = request; return { ok: true, status: "created" };
      case "capture_browser": state.captured = { username: request.username, password: request.password }; return { ok: true, stored: true, pending_token: "tok-1" };
      case "pending_browser": return { ok: true, pending: true, pending_token: "tok-1", username: state.captured?.username || "alice", status: "new", age_ms: 0 };
      case "save_pending_browser": state.saved = request.pending_token; state.savedPending = request; return { ok: true };
      case "discard_pending_browser": state.discarded = request.pending_token; return { ok: true };
      case "clear_pending_browser": state.cleared = (state.cleared || 0) + 1; return { ok: true };
      default: return null;
    }
  };
}

async function capturedPage(extraHtml = "") {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM + extraHtml, respond: saveResponder(state) });
  const { document: d } = p;
  d.getElementById("user").value = "alice";
  d.getElementById("pw").value = "hunter2";
  p.trusted(d.getElementById("login"), "submit", { submitter: d.getElementById("submit") }, p.impls.SubmitEventImpl);
  await p.tick(4);
  assert.equal(p.sent("capture_browser").length, 1, "trusted submit captures the attempt");
  assert.deepEqual(state.captured, { username: "alice", password: "hunter2" });
  return { p, state };
}

async function checkPending(p) {
  await p.command("check_pending_save"); // schedules [80, 500, 1400] ms checks
  await p.sleep(140);
  await p.tick(4);
}

test("save outcome: the login field disappearing after submit prompts to save", async () => {
  const { p } = await capturedPage();
  p.clock.now += 1000;
  p.document.getElementById("login").remove();
  await checkPending(p);
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /Save this login\?/);
  assert.match(p.panelText(), /alice/);
});

test("save flow: the Save click mints a nonce with begin_gesture_browser and forwards it to save_pending_browser", async () => {
  const { p, state } = await capturedPage();
  p.clock.now += 1000;
  p.document.getElementById("login").remove();
  await checkPending(p);
  assert.match(p.panelText(), /Save this login\?/);
  assert.equal(p.sent("begin_gesture_browser").length, 0, "nothing is minted before the user clicks");
  clickPanelButton(p, "Save login");
  await p.tick(8);
  assert.equal(state.saved, "tok-1");
  assert.equal(state.minted, 1);
  const mint = p.sent("begin_gesture_browser")[0], save = p.sent("save_pending_browser")[0];
  assert.equal(mint.user_gesture, true);
  assert.equal(save.gesture_nonce, NONCE_SAVE);
  assert.equal(save.user_gesture, true);
  assert.equal(save.operation_id, mint.operation_id, "same operation: the nonce is bound to this request context");
  assert.equal(save.session_id, undefined);
  assert.equal(p.panelVisible(), false);
});

test("save flow: manual Save login (popup) uses check_browser without session_id, then begin_gesture_browser + save_browser", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, respond: saveResponder(state) });
  p.document.getElementById("user").value = "alice";
  p.document.getElementById("pw").value = "hunter2";
  const reply = await p.command("save_current");
  assert.equal(reply.ok, true);
  await p.tick(6);
  assert.deepEqual(state.checked, { username: "alice", password: "hunter2" });
  assert.match(p.panelText(), /Save this login\?/);
  clickPanelButton(p, "Save");
  await p.tick(8);
  assert.ok(state.savedDirect, "save_browser reached the broker");
  assert.equal(state.savedDirect.gesture_nonce, NONCE_SAVE);
  assert.equal(state.savedDirect.user_gesture, true);
  assert.equal(state.savedDirect.session_id, undefined, "check_browser no longer returns a lease and none is forwarded");
  assert.equal(state.savedDirect.operation_id, p.sent("check_browser")[0].operation_id);
  assert.equal(p.sent("begin_gesture_browser")[0].operation_id, state.savedDirect.operation_id);
  assert.equal(p.panelVisible(), false);
});

test("save flow: an expired/invalid nonce on save is re-minted once, then the click-again message is shown", async () => {
  const state = {};
  const inner = saveResponder(state);
  let saves = 0;
  const p = await loaded({ html: LOGIN_FORM, respond: async r => r.type === "save_browser" ? (saves++, { ok: false, error: "gesture_nonce_invalid" }) : inner(r) });
  p.document.getElementById("user").value = "alice";
  p.document.getElementById("pw").value = "hunter2";
  await p.command("save_current");
  await p.tick(6);
  clickPanelButton(p, "Save");
  await p.tick(10);
  assert.equal(saves, 2);
  assert.equal(state.minted, 2);
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /Click again/);
});

test("save outcome: a same-document URL change after submit prompts to save", async () => {
  const { p } = await capturedPage();
  p.clock.now += 1000;
  p.window.history.pushState({}, "", "/dashboard");
  await checkPending(p);
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /Save this login\?/);
});

test("save outcome: a visible localized failure message suppresses the prompt", async () => {
  const { p } = await capturedPage(`<div id="err" role="alert" style="display:none"></div>`);
  const err = p.document.getElementById("err");
  err.textContent = "Nieprawidłowe hasło. Spróbuj ponownie.";
  err.style.display = "block";
  p.clock.now += 1000;
  p.window.history.pushState({}, "", "/login?failed=1");
  await checkPending(p);
  assert.equal(p.panelVisible(), false, "URL changed but a failure banner is visible");
  p.clock.now += 5000;
  await checkPending(p);
  assert.equal(p.panelVisible(), false, "still suppressed after the uncertainty window");
});

test("save outcome: unchanged login surface waits, then asks explicitly once uncertain", async () => {
  const { p } = await capturedPage();
  p.clock.now += 1000;
  await checkPending(p);
  assert.equal(p.panelVisible(), false, "within the wait window nothing is shown");
  p.clock.now += 4000;
  await checkPending(p);
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /Did you just sign in\?/);
});

test("save outcome: no prompt when the site turned save prompts off", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, respond: saveResponder(state), blockedOrigins: ["https://example.test"] });
  p.document.getElementById("pw").value = "hunter2";
  p.trusted(p.document.getElementById("login"), "submit", {}, p.impls.SubmitEventImpl);
  await p.tick(4);
  assert.equal(p.sent("capture_browser").length, 0);
});

test("a localized logout control discards the pending capture", async () => {
  const { p, state } = await capturedPage(`<a id="out" href="/konto">Wyloguj się</a>`);
  p.trusted(p.document.getElementById("out"), "pointerdown", { composed: true }, p.impls.MouseEventImpl);
  await p.tick(6);
  assert.ok(state.cleared >= 1, "clear_pending_browser sent");
  assert.equal(state.discarded, "tok-1");
});

test("shadow DOM: a trusted submit inside an open shadow root is captured", async () => {
  const state = {};
  const p = createPage({ html: `<div id="host"></div>`, respond: saveResponder(state) });
  const root = p.openShadow(p.document.getElementById("host"), `<form id="f" action="/s" method="post"><input id="u" type="email" name="email"><input id="pw" type="password"><button type="submit">Log in</button></form>`);
  p.load();
  await p.tick();
  assert.equal(p.fieldIcons().length, 1);
  root.getElementById("u").value = "bob@example.test";
  root.getElementById("pw").value = "pw";
  p.trusted(root.getElementById("f"), "submit", {}, p.impls.SubmitEventImpl);
  await p.tick(4);
  assert.equal(p.sent("capture_browser").length, 1, "submit does not compose; the shadow root itself is listened to");
  assert.deepEqual(state.captured, { username: "bob@example.test", password: "pw" });
});

test("untrusted (script-dispatched) submit events are ignored", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: saveResponder({}) });
  p.document.getElementById("pw").value = "hunter2";
  p.document.getElementById("login").dispatchEvent(new p.window.Event("submit", { bubbles: true, cancelable: true }));
  await p.tick(4);
  assert.equal(p.sent("capture_browser").length, 0);
});

test("messages from a foreign extension id are ignored by the command listener", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: fillResponder() });
  const result = p.commandListeners[0]({ command: "fill_current" }, { id: "imposter" }, () => { throw new Error("replied to imposter"); });
  assert.equal(result, false);
  await p.tick(4);
  assert.equal(p.sent("begin_browser").length, 0);
});

// Licensing revision 2: a full free vault refuses new logins with a structured
// item_limit reply; the save panel must say so instead of failing silently.
const ITEM_LIMIT_TEXT = "Your free LocalGateKeys holds 4 items. Upgrade to Pro for unlimited.";
const ITEM_LIMIT_REPLY = { ok: false, error: "item_limit", limit: 4 };

test("item limit: manual save on a full free vault shows the upgrade message", async () => {
  const state = {};
  const inner = saveResponder(state);
  const p = await loaded({ html: LOGIN_FORM, respond: async r => r.type === "save_browser" ? { ...ITEM_LIMIT_REPLY } : inner(r) });
  p.document.getElementById("user").value = "alice";
  p.document.getElementById("pw").value = "hunter2";
  await p.command("save_current");
  await p.tick(6);
  clickPanelButton(p, "Save");
  await p.tick(8);
  assert.equal(p.panelVisible(), true, "the refusal is shown, not swallowed");
  assert.ok(p.panelText().includes(ITEM_LIMIT_TEXT), p.panelText());
  clickPanelButton(p, "Close");
  assert.equal(p.panelVisible(), false);
});

test("item limit: automatic save prompt on a full free vault shows the upgrade message", async () => {
  const state = {};
  const inner = saveResponder(state);
  const p = await loaded({ html: LOGIN_FORM, respond: async r => r.type === "save_pending_browser" ? { ...ITEM_LIMIT_REPLY } : inner(r) });
  const { document: d } = p;
  d.getElementById("user").value = "alice";
  d.getElementById("pw").value = "hunter2";
  p.trusted(d.getElementById("login"), "submit", { submitter: d.getElementById("submit") }, p.impls.SubmitEventImpl);
  await p.tick(4);
  p.clock.now += 1000;
  d.getElementById("login").remove();
  await checkPending(p);
  clickPanelButton(p, "Save login");
  await p.tick(8);
  assert.equal(p.panelVisible(), true);
  assert.ok(p.panelText().includes(ITEM_LIMIT_TEXT), p.panelText());
});

test("item limit: without a host message the panel builds the text from the reported limit", async () => {
  const state = {};
  const inner = saveResponder(state);
  const p = await loaded({ html: LOGIN_FORM, respond: async r => r.type === "save_browser" ? { ok: false, error: "item_limit", limit: 9 } : inner(r) });
  p.document.getElementById("user").value = "alice";
  p.document.getElementById("pw").value = "hunter2";
  await p.command("save_current");
  await p.tick(6);
  clickPanelButton(p, "Save");
  await p.tick(8);
  assert.ok(p.panelText().includes("Your free LocalGateKeys holds 9 items. Upgrade to Pro for unlimited."), p.panelText());
});

async function loadedPage(options) { const p = createPage(options); p.load(); await p.tick(); return p; }
test("identity icons: post titles, chat boxes and lone guessed fields get none; real address forms still do", async () => {
  const none = [
    `<form><textarea name="title" placeholder="Title"></textarea><textarea placeholder="Body text (optional)"></textarea></form>`,
    `<form><input type="text" name="title" placeholder="Title*"></form>`,
    `<div><textarea placeholder="Reply to the assistant..."></textarea></div>`,
    `<form><input type="text" name="site" placeholder="Search site"></form>`,
    `<div role="search"><input type="text" name="city" placeholder="City"><input type="text" name="country"></div>`,
  ];
  for (const html of none) {
    const p = await loadedPage({ html });
    assert.equal(p.identityIcons().length, 0, html);
  }
  const p = await loadedPage({ html: `<form><input type="text" name="first_name"><input type="text" name="last_name"><input type="text" name="city"></form>` });
  assert.equal(p.identityIcons().length, 3);
  const q = await loadedPage({ html: `<form><input type="text" name="job_title" placeholder="Job title"><input type="text" name="company"></form>` });
  assert.equal(q.identityIcons().length, 2);
  const r = await loadedPage({ html: `<form><input type="email" name="contact"></form>` });
  assert.equal(r.identityIcons().length, 1, "explicit type=email still counts on its own");
});
