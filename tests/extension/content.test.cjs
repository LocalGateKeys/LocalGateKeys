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
function panelButtons(p) { const root = p.panelRoot(); return root ? Array.from(root.querySelectorAll("button")) : []; }
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
  assert.match(a, /^[a-km-np-zA-HJ-NP-Z2-9!@#$%^&*()\-_=+[\]{}:,.?]+$/, "no look-alike characters by default");
  const given = await loaded({ html: `<form action="/register" method="post"><input id="a" type="password" autocomplete="new-password"></form>` });
  assert.equal((await given.command("generate_new", { value: "Horse-Battery-Staple-42" })).ok, true);
  assert.equal(given.document.getElementById("a").value, "Horse-Battery-Staple-42", "the popup generator's value is used");
  const bad = await loaded({ html: `<form action="/register" method="post"><input id="a" type="password" autocomplete="new-password"></form>` });
  assert.equal((await bad.command("generate_new", { value: "ab\ncdefghij" })).ok, true);
  assert.equal(bad.document.getElementById("a").value.length, 24, "an invalid handed-over value is replaced by a fresh one");
  assert.equal(p.panelVisible(), true);
  assert.match(p.panelText(), /Password generated/);

  const q = await loaded({ html: `<form action="https://evil.test/register" method="post"><input id="a" type="password" autocomplete="new-password"></form>` });
  const refused = await q.command("generate_new");
  assert.equal(refused.ok, false);
  assert.equal(q.document.getElementById("a").value, "");
});

test("generate_new finds new-password fields without autocomplete (hint, pair, sign-up URL)", async () => {
  const hint = await loaded({ html: `<form action="/x" method="post"><label for="a">Create password</label><input id="a" type="password" name="pw"></form>` });
  assert.equal((await hint.command("generate_new")).ok, true);
  assert.equal(hint.document.getElementById("a").value.length, 24);

  const pair = await loaded({ html: `<form action="/x" method="post"><input id="a" type="password" name="pw"><input id="b" type="password" name="pw2"></form>` });
  assert.equal((await pair.command("generate_new")).ok, true);
  assert.equal(pair.document.getElementById("a").value, pair.document.getElementById("b").value);

  const signup = await loaded({ url: "https://example.test/signup", html: `<form action="/x" method="post"><input id="a" type="password" name="password"></form>` });
  assert.equal((await signup.command("generate_new")).ok, true);

  const login = await loaded({ html: `<form action="/x" method="post"><input id="a" type="password" name="password"></form>` });
  assert.equal((await login.command("generate_new")).ok, false, "plain sign-in field is never a new password");
  const change = await loaded({ html: `<form action="/x" method="post"><input id="o" type="password" name="old_password"><input id="a" type="password" name="pw"></form>` });
  assert.equal((await change.command("generate_new")).ok, false, "a current/old field in the pair blocks the pair rule");
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
  // The username is an editable field in the extension frame.
  assert.equal(p.panelRoot().querySelector("label.field input").value, "alice");
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
  await p.tick();
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

// ---- Inline account menu (sub-plan 05): the field icon opens the picker under the field.
const SIGNUP_FORM = `<form id="signup" action="/register" method="post">
  <input id="user" type="text" name="username" autocomplete="username">
  <input id="np" type="password" name="password" autocomplete="new-password">
  <input id="np2" type="password" name="confirm" autocomplete="new-password">
</form>`;
const CHANGE_FORM = `<form id="change" action="/password" method="post">
  <input id="cur" type="password" name="current" autocomplete="current-password">
  <input id="np" type="password" name="new" autocomplete="new-password">
</form>`;
const iconButtonOf = (p, host) => p.shadows.get(host).querySelector("button");
const generateIcons = p => Array.from(p.document.querySelectorAll("[data-localgatekeys-generate-icon]"));
const clickIcon = (p, host) => p.trusted(iconButtonOf(p, host), "click", { composed: true }, p.impls.MouseEventImpl);
const closePage = p => p.window.dispatchEvent(new p.window.Event("pagehide"));
// A key press in the panel. Enter on a focused button that nothing
// cancelled activates it with a trusted click (detail 0), as browsers do.
function key(p, k) {
  const root = p.panelRoot();
  const target = root.activeElement || root.querySelector("button");
  const open = p.trusted(target, "keydown", { key: k, composed: true }, p.impls.KeyboardEventImpl);
  if (k === "Enter" && open && target.tagName === "BUTTON") p.trusted(target, "click", { composed: true, detail: 0 }, p.impls.MouseEventImpl);
}

test("inline menu: the field icon opens the account picker anchored under the field at the field's width", async () => {
  const p = createPage({ html: LOGIN_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS }) });
  p.setRect(p.document.getElementById("pw"), { left: 100, top: 200, width: 360, height: 32 });
  p.load(); await p.tick();
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  const host = p.panelHost();
  assert.match(p.panelText(), /Choose an account/);
  assert.equal(host.style.left, "100px");
  assert.equal(host.style.top, "236px");
  assert.equal(host.style.width, "360px");
  closePage(p);
});

test("inline menu: near the bottom of the window the menu opens above the field", async () => {
  const p = createPage({ html: LOGIN_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS }) });
  const h = p.window.innerHeight;
  p.setRect(p.document.getElementById("pw"), { left: 100, top: h - 60, width: 300, height: 32 });
  p.load(); await p.tick();
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  const host = p.panelHost();
  const r = host.getBoundingClientRect();
  assert.ok(r.bottom <= h - 60, `menu bottom ${r.bottom} must be above the field top ${h - 60}`);
  assert.equal(host.style.top, `${h - 60 - 4 - r.height}px`);
  closePage(p);
});

test("inline menu: Enter on a tampered menu fills nothing", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS }) });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  p.panelHost().style.setProperty("opacity", "0", "important");
  key(p, "Enter");
  await p.tick(8);
  assert.equal(p.sent("get_browser").length, 0);
  assert.equal(p.document.getElementById("pw").value, "");
  assert.match(p.panelText(), /hid, moved or covered/);
  closePage(p);
});

test("inline menu: a narrow field still gets a 280 px menu", async () => {
  const p = createPage({ html: LOGIN_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS }) });
  p.setRect(p.document.getElementById("pw"), { left: 40, top: 100, width: 120, height: 30 });
  p.load(); await p.tick();
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.equal(p.panelHost().style.width, "280px");
  closePage(p);
});

test("inline menu: ArrowDown then Enter fills the second account; Escape closes", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS }) });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  key(p, "ArrowDown");
  key(p, "Enter");
  await p.tick(8);
  assert.equal(p.sent("get_browser")[0].entry_id, "e2");
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.equal(p.panelVisible(), true);
  key(p, "Escape");
  await p.tick(2);
  assert.equal(p.panelVisible(), false);
  closePage(p);
});

test("inline menu: an untrusted Enter from the page does nothing", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS }) });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  const root = p.panelRoot();
  root.querySelector("button").dispatchEvent(new p.window.KeyboardEvent("keydown", { key: "Enter", bubbles: true, composed: true }));
  await p.tick(8);
  assert.equal(p.sent("get_browser").length, 0);
  closePage(p);
});

test("inline menu: Generate row only on a sign-up form; it fills both new-password fields", async () => {
  const login = await loaded({ html: LOGIN_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS }) });
  assert.equal(generateIcons(login).length, 0);
  clickIcon(login, login.fieldIcons()[0]);
  await login.tick(8);
  assert.ok(!panelButtons(login).some(b => b.textContent.includes("Generate a password")));
  closePage(login);

  const p = await loaded({ html: SIGNUP_FORM, respond: fillResponder() });
  assert.equal(p.fieldIcons().length, 0, "no account menu on new-password fields");
  assert.equal(generateIcons(p).length, 1, "one generate icon per sign-up form");
  clickIcon(p, generateIcons(p)[0]);
  await p.tick(4);
  assert.equal(p.sent("begin_browser").length, 0, "the generator needs no vault access");
  const shown = p.panelText();
  clickPanelButton(p, "Fill on page");
  await p.tick(4);
  const a = p.document.getElementById("np").value, b = p.document.getElementById("np2").value;
  assert.equal(a.length, 20);
  assert.ok(shown.includes(a), "the suggestion shown in the box is the one filled");
  assert.equal(a, b);
  closePage(p);
});

test("inline menu: change-password form offers accounts on the current field and Generate on the new field", async () => {
  const p = await loaded({ html: CHANGE_FORM, respond: fillResponder({ choices: TWO_ACCOUNTS }) });
  assert.equal(p.fieldIcons().length, 1);
  assert.equal(p.S().currentPassword(p.document.getElementById("cur")), true);
  assert.equal(p.S().currentPassword(p.document.getElementById("np")), false);
  assert.equal(generateIcons(p).length, 1);
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.match(p.panelText(), /Bob/);
  assert.ok(!panelButtons(p).some(b => b.textContent.includes("Generate a password")));
  key(p, "Escape"); // the open menu covers the next field's icon
  await p.tick(2);
  clickIcon(p, generateIcons(p)[0]);
  await p.tick(4);
  clickPanelButton(p, "Fill on page");
  await p.tick(4);
  assert.equal(p.document.getElementById("np").value.length, 20);
  assert.equal(p.document.getElementById("cur").value, "", "the current password is never generated");
  closePage(p);
});

test("test_inline_menu_hidden_when_policy_fill_never", async () => {
  // The broker leaves fill:never logins out; with none left it refuses.
  const p = await loaded({ html: LOGIN_FORM, respond: async r => r.type === "begin_browser" ? { ok: false, error: "fill_disabled" } : null });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.doesNotMatch(p.panelText(), /Choose an account/);
  assert.equal(p.sent("get_browser").length, 0);
  const empty = await loaded({ html: LOGIN_FORM, respond: async r => r.type === "begin_browser" ? { ok: true, grant: "g", choices: [], profile: { name: "Home" } } : { ok: true } });
  clickIcon(empty, empty.fieldIcons()[0]);
  await empty.tick(8);
  assert.doesNotMatch(empty.panelText(), /Choose an account/, "no empty menu");
  // "Never for this site": no inline icons on that origin.
  const never = await loaded({ html: `${LOGIN_FORM}<form><input type="password" autocomplete="new-password"></form>`, blockedOrigins: ["https://example.test"] });
  assert.equal(never.fieldIcons().length, 0);
  assert.equal(generateIcons(never).length, 0);
  for (const x of [p, empty, never]) closePage(x);
});

test("test_inline_menu_origin_is_own_document_origin", async () => {
  // The script turns itself off in cross-origin login frames (no inline menu there). Wherever it
  // runs, its own document's origin is what msg() sends and what the per-site setting is checked
  // against, never another page's.
  const p = await loaded({ html: LOGIN_FORM, url: "https://login.idp.test/frame", blockedOrigins: ["https://example.test"], respond: fillResponder({ choices: TWO_ACCOUNTS }) });
  assert.equal(p.fieldIcons().length, 1, "the top page's setting does not hide the frame's menu");
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.equal(p.sent("begin_browser")[0].origin, "https://login.idp.test");
  assert.match(p.panelText(), /https:\/\/login\.idp\.test/);
  closePage(p);
  const blocked = await loaded({ html: LOGIN_FORM, url: "https://login.idp.test/frame", blockedOrigins: ["https://login.idp.test"] });
  assert.equal(blocked.fieldIcons().length, 0);
  closePage(blocked);
});

// ---- Phishing shield: Verified site state and the lookalike submit guard (sub-plan 09, task 4).
// The verdict comes from the app (classify_site_browser); the content script never sees the
// saved origins, only the verdict and, for a lookalike, the host it imitates.
function verdictResponder(verdict, state = {}) {
  const inner = saveResponder(state);
  return async request => {
    if (request.type === "classify_site_browser") { state.classified = (state.classified || 0) + 1; return verdict; }
    return inner(request);
  };
}
const LOOKALIKE = { ok: true, kind: "lookalike", reason: "edit-distance", matched: "example.com" };
const OTHER_SUFFIX = { ok: true, kind: "lookalike", reason: "other-suffix", matched: "www.amazon.com", pair: "0123456789abcdef0123456789abcdef" };
function iconButton(p) { return p.shadows.get(p.fieldIcons()[0]).querySelector("button"); }
async function focusField(p, id = "pw") {
  p.trusted(p.document.getElementById(id), "focusin", { bubbles: true });
  await p.tick(6);
}
function typedLogin(p) {
  p.document.getElementById("user").value = "alice";
  p.document.getElementById("pw").value = "hunter2";
}
function submitLogin(p) {
  return p.trusted(p.document.getElementById("login"), "submit", { submitter: p.document.getElementById("submit") }, p.impls.SubmitEventImpl);
}

test("site verdict: nothing is sent on load; focusing a login field asks once and marks the fill icon", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, url: "https://example.com/login", respond: verdictResponder({ ok: true, kind: "exact", reason: "same-origin" }, state) });
  assert.equal(p.messages.length, 0, "no native call on page load");
  await focusField(p);
  await focusField(p, "user");
  assert.equal(state.classified, 1, "one verdict per document");
  const message = p.sent("classify_site_browser")[0];
  assert.equal(message.origin, "https://example.com");
  assert.deepEqual(Object.keys(message).sort(), ["document_key", "operation_id", "origin", "type"]);
  assert.equal(iconButton(p).dataset.verdict, "exact");
  assert.match(iconButton(p).title, /Verified site/);
});

test("site verdict: the popup's site_state command returns the cleaned verdict", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: verdictResponder({ ...LOOKALIKE, extra: "dropped", pair: "zz" }) });
  const reply = await p.command("site_state");
  assert.deepEqual(JSON.parse(JSON.stringify(reply)), { ok: true, verdict: { kind: "lookalike", reason: "edit-distance", matched: "example.com", pair: null } });
  assert.equal(iconButton(p).dataset.verdict, "lookalike");
  const locked = await loaded({ html: LOGIN_FORM, respond: verdictResponder({ ok: true, locked: true, unchecked: true }) });
  assert.deepEqual(JSON.parse(JSON.stringify(await locked.command("site_state"))), { ok: true, verdict: null });
});

test("lookalike guard: a credential submit is stopped and asks 'Is this the right site?' first", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, url: "https://examp1e.com/login", respond: verdictResponder(LOOKALIKE, state) });
  let pageSaw = 0;
  p.document.getElementById("login").addEventListener("submit", () => pageSaw++);
  await focusField(p);
  typedLogin(p);
  const notCancelled = submitLogin(p);
  await p.tick(6);
  assert.equal(notCancelled, false, "the submit was cancelled");
  assert.equal(pageSaw, 0, "the page never saw the credential submit");
  assert.equal(p.sent("capture_browser").length, 0, "nothing is captured before the user answers");
  assert.match(p.panelText(), /Is this the right site\?/);
  assert.match(p.panelText(), /examp1e\.com/);
  assert.deepEqual(panelButtons(p).map(b => b.textContent), ["Go back", "Continue on examp1e.com"], "Ruling T4: Go back first, then the real host");
  assert.equal(panelButtons(p)[0].className, "primary", "Go back is the default");
  // Confirming continues the same submit once; the guard does not ask again in this document.
  clickPanelButton(p, "Continue on examp1e.com");
  await p.tick(8);
  assert.equal(pageSaw, 1, "the form is submitted after the user confirms");
  assert.equal(p.sent("capture_browser").length, 1);
  submitLogin(p);
  await p.tick(6);
  assert.equal(pageSaw, 2, "no second question in this document");
});

test("lookalike guard: Go back closes the panel and submits nothing", async () => {
  const p = await loaded({ html: LOGIN_FORM, url: "https://examp1e.com/login", respond: verdictResponder(LOOKALIKE) });
  let pageSaw = 0, back = 0;
  p.document.getElementById("login").addEventListener("submit", () => pageSaw++);
  p.window.history.pushState({}, "", "/login?step=2"); // a tab with history
  p.window.history.back = () => { back++; };
  await focusField(p);
  typedLogin(p);
  submitLogin(p);
  await p.tick(6);
  clickPanelButton(p, "Go back");
  await p.tick(6);
  assert.equal(p.panelVisible(), false);
  assert.equal(back, 1);
  assert.equal(p.document.getElementById("pw").value, "", "the typed password is blanked");
  assert.equal(pageSaw, 0);
  assert.equal(p.sent("capture_browser").length, 0);
});

test("lookalike guard: verified, related and new sites submit without a question", async () => {
  for (const verdict of [{ ok: true, kind: "exact", reason: "same-origin" }, { ok: true, kind: "unknown", reason: "no-match" }, { ok: true, kind: "related", reason: "same-site" }]) {
    const p = await loaded({ html: LOGIN_FORM, respond: verdictResponder(verdict) });
    let pageSaw = 0;
    p.document.getElementById("login").addEventListener("submit", () => pageSaw++);
    await focusField(p);
    typedLogin(p);
    assert.equal(submitLogin(p), true);
    await p.tick(6);
    assert.equal(pageSaw, 1, verdict.kind);
    assert.doesNotMatch(p.panelText(), /right site|same account/, verdict.kind);
  }
});

test("lookalike guard: the manual save prompt asks first, then shows the save panel", async () => {
  const p = await loaded({ html: LOGIN_FORM, url: "https://examp1e.com/login", respond: verdictResponder(LOOKALIKE) });
  typedLogin(p);
  await p.command("save_current");
  await p.tick(8);
  assert.match(p.panelText(), /Is this the right site\?/);
  assert.equal(p.sent("check_browser").length, 0);
  clickPanelButton(p, "Continue on examp1e.com");
  await p.tick(8);
  assert.match(p.panelText(), /Save this login\?/);
});

test("other-suffix: softer question, asked once, and 'Same account' is remembered for that origin pair", async () => {
  const p = await loaded({ html: LOGIN_FORM, url: "https://www.amazon.de/login", respond: verdictResponder(OTHER_SUFFIX) });
  let pageSaw = 0;
  p.document.getElementById("login").addEventListener("submit", () => pageSaw++);
  await focusField(p);
  typedLogin(p);
  submitLogin(p);
  await p.tick(6);
  assert.match(p.panelText(), /Is this the same account as www\.amazon\.com\?/);
  assert.doesNotMatch(p.panelText(), /right site/);
  clickPanelButton(p, "Same account");
  await p.tick(8);
  assert.equal(pageSaw, 1);
  const remembered = [...p.storage.lookalike_same_account_pairs];
  assert.deepEqual(remembered, [OTHER_SUFFIX.pair], "only the opaque pair id is stored, never a saved origin");
  // A later visit with the same pair: no question, shown as a related site.
  const again = await loaded({ html: LOGIN_FORM, url: "https://www.amazon.de/login", respond: verdictResponder(OTHER_SUFFIX) });
  again.storage.lookalike_same_account_pairs = remembered;
  let againSaw = 0;
  again.document.getElementById("login").addEventListener("submit", () => againSaw++);
  await focusField(again);
  typedLogin(again);
  submitLogin(again);
  await again.tick(6);
  assert.equal(againSaw, 1);
  assert.doesNotMatch(again.panelText(), /same account/);
  assert.equal(iconButton(again).dataset.verdict, "related");
  // Another pair (another saved site) still asks.
  const other = await loaded({ html: LOGIN_FORM, url: "https://www.amazon.de/login", respond: verdictResponder({ ...OTHER_SUFFIX, pair: "f".repeat(32) }) });
  other.storage.lookalike_same_account_pairs = remembered;
  await focusField(other);
  typedLogin(other);
  submitLogin(other);
  await other.tick(6);
  assert.match(other.panelText(), /same account/);
});

test("mixed-script lookalike without a saved match names the page host on the button", async () => {
  const p = await loaded({ html: LOGIN_FORM, url: "https://xn--bnk-6cd.test/login", respond: verdictResponder({ ok: true, kind: "lookalike", reason: "mixed-script", matched: null, local: true }) });
  await focusField(p);
  typedLogin(p);
  submitLogin(p);
  await p.tick(6);
  assert.match(p.panelText(), /Is this the right site\?/);
  assert.match(p.panelText(), /different alphabets/);
  assert.ok(panelButtons(p).some(b => b.textContent === "Continue on xn--bnk-6cd.test"));
});

test("lookalike guard: Go back in a fresh tab (no history) blanks the password and leaves for about:blank", async () => {
  const p = await loaded({ html: LOGIN_FORM, url: "https://examp1e.com/login", respond: verdictResponder(LOOKALIKE) });
  let back = 0, pageSaw = 0;
  p.window.history.back = () => { back++; };
  p.document.getElementById("login").addEventListener("submit", () => pageSaw++);
  assert.equal(p.window.history.length, 1);
  await focusField(p);
  typedLogin(p);
  submitLogin(p);
  await p.tick(6);
  clickPanelButton(p, "Go back");
  await p.tick(6);
  assert.equal(back, 0, "history.back() would do nothing in a fresh tab");
  assert.equal(p.document.getElementById("pw").value, "");
  assert.equal(p.panelVisible(), false);
  assert.equal(pageSaw, 0);
});

test("lookalike guard: an untrusted (script-fired) submit is not held and shows nothing", async () => {
  const p = await loaded({ html: LOGIN_FORM, url: "https://examp1e.com/login", respond: verdictResponder(LOOKALIKE) });
  await focusField(p);
  typedLogin(p);
  const event = new p.window.Event("submit", { bubbles: true, cancelable: true });
  assert.equal(p.document.getElementById("login").dispatchEvent(event), true);
  await p.tick(6);
  assert.equal(p.panelVisible(), false);
});

test("lookalike guard: a verdict that arrives after the submit does not hold it after the fact", async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const inner = verdictResponder(LOOKALIKE);
  const p = await loaded({ html: LOGIN_FORM, url: "https://examp1e.com/login", respond: async r => r.type === "classify_site_browser" ? (await gate, LOOKALIKE) : inner(r) });
  let pageSaw = 0;
  p.document.getElementById("login").addEventListener("submit", () => pageSaw++);
  p.trusted(p.document.getElementById("pw"), "focusin", { bubbles: true });
  typedLogin(p);
  assert.equal(submitLogin(p), true, "unknown verdict at submit time: the submit goes through");
  assert.equal(pageSaw, 1);
  release();
  await p.tick(8);
  assert.equal(pageSaw, 1, "nothing is replayed or cancelled later");
});

test("lookalike guard: captureSubmission while the guard is open does not stack a second panel", async () => {
  const p = await loaded({ html: LOGIN_FORM, url: "https://examp1e.com/login", respond: verdictResponder(LOOKALIKE) });
  await focusField(p);
  typedLogin(p);
  submitLogin(p);
  await p.tick(6);
  const host = p.panelHost();
  const before = p.panelText();
  // The Enter key path calls captureSubmission directly.
  p.trusted(p.document.getElementById("pw"), "keydown", { key: "Enter", bubbles: true }, p.impls.KeyboardEventImpl);
  await p.tick(6);
  assert.equal(p.panelHost(), host);
  assert.equal(p.panelText(), before);
  assert.equal(p.document.querySelectorAll("html > div").length, 1, "one panel host");
  assert.equal(p.sent("capture_browser").length, 0);
});

test("other-suffix: a pair remembered for amazon.de does not clear the question on amazon.co.uk", async () => {
  const de = await loaded({ html: LOGIN_FORM, url: "https://www.amazon.de/login", respond: verdictResponder(OTHER_SUFFIX) });
  await focusField(de);
  typedLogin(de);
  submitLogin(de);
  await de.tick(6);
  clickPanelButton(de, "Same account");
  await de.tick(8);
  const remembered = [...de.storage.lookalike_same_account_pairs];
  const uk = await loaded({ html: LOGIN_FORM, url: "https://www.amazon.co.uk/login", respond: verdictResponder({ ...OTHER_SUFFIX, pair: "a".repeat(32) }) });
  uk.storage.lookalike_same_account_pairs = remembered;
  await focusField(uk);
  typedLogin(uk);
  assert.equal(submitLogin(uk), false);
  await uk.tick(6);
  assert.match(uk.panelText(), /Is this the same account as www\.amazon\.com\?/);
});

test("site verdict: a verdict older than a minute is asked again; a locked answer clears it", async () => {
  let answer = { ok: true, kind: "lookalike", reason: "edit-distance", matched: "example.com" };
  const inner = verdictResponder(LOOKALIKE);
  const p = await loaded({ html: LOGIN_FORM, url: "https://examp1e.com/login", respond: async r => r.type === "classify_site_browser" ? answer : inner(r) });
  await focusField(p);
  assert.equal(iconButton(p).dataset.verdict, "lookalike");
  answer = { ok: true, locked: true, unchecked: true };
  p.clock.now += 61000;
  await focusField(p);
  assert.equal(p.sent("classify_site_browser").length, 2);
  assert.equal(iconButton(p).dataset.verdict, undefined, "the vault locked: no stale verdict is kept");
  typedLogin(p);
  assert.equal(submitLogin(p), true);
});

// ---- Ruling T4b: a never-seen site asking for a username saved for another site.
function newSiteResponder(elsewhere, state = {}) {
  const inner = verdictResponder({ ok: true, kind: "unknown", reason: "no-match" }, state);
  return async request => {
    if (request.type === "new_site_username_browser") { state.asked = [...(state.asked || []), request]; return { ok: true, elsewhere }; }
    return inner(request);
  };
}
function typeInto(p, id, value) {
  const field = p.document.getElementById(id);
  field.value = value;
  p.trusted(field, "input", { bubbles: true });
}

test("new site: a typed username saved elsewhere shows a soft note after the user's submit", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, url: "https://secure-login-verify.test/login", respond: newSiteResponder(true, state) });
  let pageSaw = 0;
  p.document.getElementById("login").addEventListener("submit", () => pageSaw++);
  await focusField(p);
  typeInto(p, "user", "alice");
  typeInto(p, "pw", "hunter2");
  assert.equal(submitLogin(p), true, "a soft note: the submit is not held");
  await p.tick(8);
  assert.equal(pageSaw, 1);
  assert.equal(state.asked.length, 1);
  assert.equal(state.asked[0].username, "alice");
  assert.equal(state.asked[0].user_gesture, true);
  assert.equal(state.asked[0].password, undefined, "the password is never sent for this check");
  assert.match(p.panelText(), /New site for this username/);
  assert.match(p.panelText(), /never for secure-login-verify\.test/);
  assert.deepEqual(panelButtons(p).map(b => b.textContent), ["Go back", "Continue on secure-login-verify.test"]);
  // Once per document.
  submitLogin(p);
  await p.tick(6);
  assert.equal(state.asked.length, 1);
});

test("new site: no note when the username is not saved elsewhere", async () => {
  const p = await loaded({ html: LOGIN_FORM, url: "https://new.test/login", respond: newSiteResponder(false) });
  await focusField(p);
  typeInto(p, "user", "alice");
  typeInto(p, "pw", "hunter2");
  submitLogin(p);
  await p.tick(8);
  assert.doesNotMatch(p.panelText(), /New site for this username/);
});

test("new site: a page cannot ask (script-set username, script-fired submit, or a known site)", async () => {
  // Username set by the page's script: never checked.
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, url: "https://new.test/login", respond: newSiteResponder(true, state) });
  await focusField(p);
  typeInto(p, "user", "alice");
  p.document.getElementById("user").value = "bob"; // changed by script after the user typed
  typeInto(p, "pw", "hunter2");
  submitLogin(p);
  await p.tick(8);
  assert.equal(state.asked, undefined);
  // Untrusted submit: never checked.
  const q = await loaded({ html: LOGIN_FORM, url: "https://new.test/login", respond: newSiteResponder(true, state) });
  await focusField(q);
  typeInto(q, "user", "alice");
  typeInto(q, "pw", "hunter2");
  q.document.getElementById("login").dispatchEvent(new q.window.Event("submit", { bubbles: true, cancelable: true }));
  await q.tick(8);
  assert.equal(state.asked, undefined);
  // Verified site: the check is only for unknown sites.
  const known = {};
  const inner = newSiteResponder(true, known);
  const r = await loaded({ html: LOGIN_FORM, url: "https://example.com/login", respond: async m => m.type === "classify_site_browser" ? { ok: true, kind: "exact", reason: "same-origin" } : inner(m) });
  await focusField(r);
  typeInto(r, "user", "alice");
  typeInto(r, "pw", "hunter2");
  submitLogin(r);
  await r.tick(8);
  assert.equal(known.asked, undefined);
});

// ---- Review R1: a capture made while the vault was locked (no verdict in the page) is
// classified by the app when it is saved after unlock; a lookalike asks the guard first.
function deferredLookalikeResponder(refusal, state = {}) {
  state.saves = [];
  return async request => {
    switch (request.type) {
      case "classify_site_browser": return { ok: true, locked: true, unchecked: true };
      case "capture_browser": return { ok: true, stored: true, pending_token: "tok-1", status: "deferred" };
      case "pending_browser": return { ok: true, pending: true, pending_token: "tok-1", username: "alice", status: "deferred", age_ms: 0 };
      case "begin_gesture_browser": return { ok: true, gesture_nonce: NONCE_SAVE, gesture_expires_in: 30 };
      case "save_pending_browser":
        state.saves.push(request);
        return request.lookalike_confirmed === true ? { ok: true, status: "created" } : refusal;
      case "discard_pending_browser": case "clear_pending_browser": return { ok: true };
      default: return null;
    }
  };
}
async function deferredPrompt(url, refusal, state) {
  const p = await loaded({ html: LOGIN_FORM, url, respond: deferredLookalikeResponder(refusal, state) });
  await focusField(p);
  typedLogin(p);
  assert.equal(submitLogin(p), true, "locked vault: no verdict, so the submit is not held");
  await p.tick(6);
  p.clock.now += 1000;
  p.document.getElementById("login").remove();
  await checkPending(p);
  assert.match(p.panelText(), /Unlock to review this login/);
  clickPanelButton(p, "Unlock to review");
  await p.tick(10);
  return p;
}
const REFUSAL = { ok: false, error: "lookalike_site", kind: "lookalike", reason: "edit-distance", matched: "example.com" };

test("R1: a deferred save the app finds to be a lookalike asks the guard, then retries confirmed", async () => {
  const state = {};
  const p = await deferredPrompt("https://examp1e.com/login", REFUSAL, state);
  assert.equal(state.saves.length, 1);
  assert.equal(state.saves[0].lookalike_confirmed, undefined, "the first save never claims a confirmation");
  assert.match(p.panelText(), /Is this the right site\?/);
  assert.match(p.panelText(), /examp1e\.com looks like example\.com/);
  clickPanelButton(p, "Continue on examp1e.com");
  await p.tick(10);
  assert.equal(state.saves.length, 2);
  assert.equal(state.saves[1].lookalike_confirmed, true);
  assert.equal(state.saves[1].pending_token, "tok-1");
  assert.equal(state.saves[1].gesture_nonce, NONCE_SAVE, "the Continue click is the gesture for the retry");
  assert.equal(p.panelVisible(), false);
});

test("R1: Go back on that guard saves nothing", async () => {
  const state = {};
  const p = await deferredPrompt("https://examp1e.com/login", REFUSAL, state);
  p.window.history.back = () => {};
  clickPanelButton(p, "Go back");
  await p.tick(10);
  assert.equal(state.saves.length, 1, "no confirmed retry");
});

test("R1: a remembered 'same account' pair retries without asking again", async () => {
  const state = {};
  const pair = "b".repeat(32);
  const refusal = { ok: false, error: "lookalike_site", kind: "lookalike", reason: "other-suffix", matched: "www.amazon.com", pair };
  const p = await loaded({ html: LOGIN_FORM, url: "https://www.amazon.de/login", respond: deferredLookalikeResponder(refusal, state) });
  p.storage.lookalike_same_account_pairs = [pair];
  await focusField(p);
  typedLogin(p);
  submitLogin(p);
  await p.tick(6);
  p.clock.now += 1000;
  p.document.getElementById("login").remove();
  await checkPending(p);
  clickPanelButton(p, "Unlock to review");
  await p.tick(12);
  assert.equal(state.saves.length, 2);
  assert.equal(state.saves[1].lookalike_confirmed, true);
  assert.doesNotMatch(p.panelText(), /same account/);
});

test("R1: an app refusal without a usable verdict is shown as an error, never retried", async () => {
  const state = {};
  const p = await deferredPrompt("https://examp1e.com/login", { ok: false, error: "lookalike_site", kind: "bogus" }, state);
  assert.equal(state.saves.length, 1);
  assert.doesNotMatch(p.panelText(), /Continue on/);
});

// ---- AI agent sign-in (agent_gate): the page asks only when a sign-in field gets focus.
function agentResponder({ choices, state = {} }) {
  const inner = fillResponder({ choices, state });
  state.asked = 0;
  return async request => {
    if (request.type === "fill_grant_browser") {
      state.asked++;
      if (!choices) return { ok: false, error: "not_found" };
      return { ok: true, agent: true, grant: "grant-agent", session_id: "s1", profile: { name: "Home" },
        gesture_nonce: NONCE_A, gesture_expires_in: 30, choices };
    }
    if (request.type === "classify_site_browser") return { ok: true, kind: "exact", reason: "same-origin" };
    return inner(request);
  };
}

test("agent fill: never on load or page focus; the user's icon click opens the picker and a second click fills", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, url: "https://login.example.com/", respond: agentResponder({ choices: [{ entry_id: "e1", username: "alice" }], state }) });
  assert.equal(p.sent("fill_grant_browser").length, 0, "no ask on page load");
  await focusField(p);
  p.document.getElementById("pw").focus();
  p.document.getElementById("pw").dispatchEvent(new p.window.FocusEvent("focusin", { bubbles: true }));
  await p.tick(8);
  assert.equal(state.asked, 0, "page focus (scripted or not) never asks for the grant");
  // A page script cannot click the icon: untrusted clicks are ignored.
  p.shadows.get(p.fieldIcons()[0]).querySelector("button").click();
  await p.tick(8);
  assert.equal(state.asked, 0);
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.equal(state.asked, 1);
  assert.equal(state.releases.length, 0, "even one approved login waits for the user's pick");
  clickPanelButton(p, "alice");
  await p.tick(8);
  assert.equal(state.releases.length, 1, "the login is released through get_browser");
  assert.equal(state.releases[0].grant, "grant-agent");
  assert.equal(p.document.getElementById("pw").value, "s3cret");
});

test("agent fill: several logins open the picker; nothing armed goes on as a normal icon fill", async () => {
  const state = {};
  const p = await loaded({ html: LOGIN_FORM, url: "https://example.com/login", respond: agentResponder({ choices: TWO_ACCOUNTS, state }) });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.equal(state.releases.length, 0, "the user picks; nothing is released yet");
  assert.match(p.panelText(), /alice/);
  assert.match(p.panelText(), /bob/);
  const none = {};
  const q = await loaded({ html: LOGIN_FORM, url: "https://example.com/login", respond: agentResponder({ choices: null, state: none }) });
  clickIcon(q, q.fieldIcons()[0]);
  await q.tick(8);
  assert.equal(none.asked, 1);
  assert.equal(q.sent("begin_browser").length, 1, "the normal fill goes on");
  assert.equal(none.releases.length, 0);
  assert.equal(q.document.getElementById("pw").value, "");
});

test("agent fill: a passkey grant fills nothing and says to use the site's passkey sign-in", async () => {
  const state = {};
  const inner = agentResponder({ choices: null, state });
  const respond = async request => request.type === "fill_grant_browser"
    ? { ok: false, error: "agent_passkey", message: "Use the passkey sign-in." } : inner(request);
  const p = await loaded({ html: LOGIN_FORM, url: "https://login.example.com/", respond });
  clickIcon(p, p.fieldIcons()[0]);
  await p.tick(8);
  assert.match(p.panelText(), /Use the passkey sign-in\./);
  assert.equal(p.sent("begin_browser").length, 0, "no normal fill starts");
  assert.equal(state.releases.length, 0);
  assert.equal(p.document.getElementById("pw").value, "");
});

test("an opaque-origin (sandboxed) document gets no fill icons and sends nothing", async () => {
  const p = await loaded({ html: LOGIN_FORM, url: "https://login.example.com/", respond: fillResponder(), selfOrigin: "null" });
  assert.equal(p.fieldIcons().length, 0);
  assert.equal(p.messages.length, 0);
});

// Review 2026-11-15 H1/M1/M2: new-password capture and identifier-first logins.
async function submitForm(html, values, state = {}) {
  const p = await loaded({ html, respond: saveResponder(state) });
  const d = p.document;
  for (const [id, v] of Object.entries(values)) d.getElementById(id).value = v;
  p.trusted(d.getElementById("f"), "submit", { submitter: d.getElementById("go") }, p.impls.SubmitEventImpl);
  await p.tick(6);
  return { p, state };
}
const NEWPW_FORM = `<form id="f" action="/pw" method="post"><input id="u" type="text" autocomplete="username" name="username">
  <input id="cur" type="password" autocomplete="current-password"><input id="n1" type="password" autocomplete="new-password">
  <input id="n2" type="password" autocomplete="new-password"><button id="go" type="submit">Save</button></form>`;
test("change-password form captures the new password, never the current one", async () => {
  const { p, state } = await submitForm(NEWPW_FORM, { u: "alice", cur: "old-pw", n1: "new-pw", n2: "new-pw" });
  assert.equal(p.sent("capture_browser").length, 1);
  assert.deepEqual(state.captured, { username: "alice", password: "new-pw" });
});
test("change-password form with a mismatched confirm captures nothing", async () => {
  const { p } = await submitForm(NEWPW_FORM, { u: "alice", cur: "old-pw", n1: "new-pw", n2: "typo" });
  assert.equal(p.sent("capture_browser").length, 0);
});
test("sign-up form (new-password only) captures the typed password", async () => {
  const html = `<form id="f" action="/join" method="post"><input id="u" type="email" name="email">
    <input id="n1" type="password" autocomplete="new-password"><button id="go" type="submit">Create account</button></form>`;
  const { p, state } = await submitForm(html, { u: "a@example.com", n1: "fresh-pw" });
  assert.equal(p.sent("capture_browser").length, 1);
  assert.deepEqual(state.captured, { username: "a@example.com", password: "fresh-pw" });
});
test("identifier-first login: the step-one username is attached to the password step", async () => {
  const state = {};
  const html = `<form id="f" action="/next" method="post"><input id="u" type="email" name="identifier"><button id="go" type="submit">Next</button></form>`;
  const { p } = await submitForm(html, { u: "bob@example.com" }, state);
  assert.equal(p.sent("step_username_browser").length, 1);
  assert.equal(p.sent("capture_browser").length, 0);
  const d = p.document;
  d.getElementById("f").innerHTML = `<input id="pw" type="password" autocomplete="current-password"><button id="go2" type="submit">Sign in</button>`;
  await p.tick(2);
  d.getElementById("pw").value = "pw-2";
  p.trusted(d.getElementById("f"), "submit", { submitter: d.getElementById("go2") }, p.impls.SubmitEventImpl);
  await p.tick(6);
  assert.deepEqual(state.captured, { username: "bob@example.com", password: "pw-2" });
});
test("final review L6: a change-password form never takes an earlier email form's value as its username", async () => {
  const state = {};
  const html = `<form id="f" action="/email" method="post"><input id="u" type="email" name="email"><button id="go" type="submit">Change email</button></form>`;
  const { p } = await submitForm(html, { u: "new-mail@example.com" }, state);
  assert.equal(p.sent("step_username_browser").length, 1);
  const d = p.document;
  d.getElementById("f").innerHTML = `<input id="cur" type="password" autocomplete="current-password">
    <input id="n1" type="password" autocomplete="new-password"><button id="go2" type="submit">Change password</button>`;
  await p.tick(2);
  d.getElementById("cur").value = "old-pw"; d.getElementById("n1").value = "new-pw";
  p.trusted(d.getElementById("f"), "submit", { submitter: d.getElementById("go2") }, p.impls.SubmitEventImpl);
  await p.tick(6);
  assert.deepEqual(state.captured, { username: "", password: "new-pw" }, "password-only: offered as an update, never as a new login");
  assert.equal(p.sent("recall_username_browser").length, 0);
});
