"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createPage } = require("./helpers.cjs");

function page(html) {
  const p = createPage({ html, scripts: ["api.js", "heuristics.js", "login-safety.js"] });
  p.load();
  return p;
}

test("safeForm rejects cross-origin actions, formaction overrides, and non-self targets", () => {
  const p = page(`
    <form id="same" action="/session" method="post"><input type="password"><button id="ok">Sign in</button></form>
    <form id="mixed" action="/session" method="post"><input type="password"><button id="ok2">Sign in</button><button id="evil" formaction="https://evil.test/steal">Sign in</button></form>
    <form id="cross" action="https://evil.test/login" method="post"><input type="password"></form>
    <form id="blank" action="/x" target="_blank"></form>
    <form id="self" action="https://example.test/x" target="_self"></form>
    <form id="bad" action="http://[::bad"></form>`);
  const { document: d, S } = p;
  const s = S();
  assert.equal(s.safeForm(d.getElementById("same")), true);
  assert.equal(s.safeForm(d.getElementById("same"), d.getElementById("ok")), true);
  assert.equal(s.safeForm(d.getElementById("mixed"), d.getElementById("evil")), false, "submitter formaction to another origin");
  assert.equal(s.safeForm(d.getElementById("mixed")), false, "any submitter posting elsewhere taints the whole form");
  assert.equal(s.safeForm(d.getElementById("mixed"), d.getElementById("ok2")), false);
  assert.equal(s.safeForm(d.getElementById("cross")), false);
  assert.equal(s.safeForm(d.getElementById("blank")), false);
  assert.equal(s.safeForm(d.getElementById("self")), true);
  assert.equal(s.safeForm(d.getElementById("bad")), false);
  assert.equal(s.safeForm(d.createElement("form")), false, "detached form");
  assert.equal(s.safeForm(d.createElement("div")), false);
});

test("snapshot refuses a cross-origin form even for a visible current-password field", () => {
  const p = page(`<form action="https://evil.test/login" method="post"><input id="pw" type="password"></form>`);
  assert.throws(() => p.S().snapshot(p.document.getElementById("pw")), /another origin/);
});

test("onTop rejects a field covered by an overlay and hidden fields", () => {
  const p = page(`<form><input id="pw" type="password"><input id="hidden" type="password" style="display:none"></form><div id="overlay"></div>`);
  const { document: d, S, setRect } = p;
  const pw = d.getElementById("pw");
  assert.equal(S().onTop(pw), true);
  assert.equal(S().currentPassword(pw), true);
  setRect(d.getElementById("overlay"), { left: 0, top: 0, width: 1024, height: 768 });
  assert.equal(S().onTop(pw), false, "overlay wins the hit test");
  assert.equal(S().visible(d.getElementById("hidden")), false);
  assert.throws(() => S().snapshot(pw), /hidden, covered/);
});

test("new-password fields are not current passwords; username-only snapshots work without a password field", () => {
  const p = page(`<form id="f" action="/next" method="post"><input id="email" type="email" autocomplete="username"></form>
                  <form><input id="np" type="password" autocomplete="new-password"></form>`);
  const { document: d, S } = p;
  const email = d.getElementById("email");
  assert.equal(S().currentPassword(d.getElementById("np")), false);
  assert.throws(() => S().snapshot(email, false), /no longer a login field/);
  const ctx = S().snapshot(email, true);
  assert.equal(ctx.usernameOnly, true);
  assert.equal(ctx.form, d.getElementById("f"));
  assert.equal(ctx.origin, "https://example.test");
  assert.equal(S().unchanged(ctx), true);
  assert.equal(S().submitCandidate(ctx), null, "username-only never auto-submits");
  email.form.setAttribute("action", "https://evil.test/next");
  assert.equal(S().unchanged(ctx), false, "action change invalidates the snapshot");
});

test("OTP detection: split boxes, explicit autocomplete, and name hints", () => {
  const p = page(`
    <div id="split">${"<input type=\"text\" maxlength=\"1\" inputmode=\"numeric\">".repeat(6)}</div>
    <div id="four">${"<input type=\"text\" maxlength=\"1\" inputmode=\"numeric\">".repeat(4)}</div>
    <input id="explicit" type="text" autocomplete="one-time-code">
    <input id="hint" type="text" name="otp_code" maxlength="6">
    <input id="user" type="text" name="username">
    <input id="short" type="text" name="verification_code" maxlength="4">`);
  const { document: d, S } = p;
  const s = S();
  const split = Array.from(d.querySelectorAll("#split input"));
  assert.equal(s.otpField(split[0]), true, "first box of a 6-box group");
  assert.equal(s.otpField(split[1]), false, "only the first box carries the icon");
  assert.equal(s.otpBoxes(split[0]).length, 6);
  const snap = s.otpSnapshot(split[0]);
  assert.equal(snap.boxes.length, 6);
  assert.equal(snap.usernameOnly, true);
  assert.equal(s.otpField(d.querySelector("#four input")), false, "4 boxes is not a code group");
  assert.equal(s.otpField(d.getElementById("explicit")), true);
  assert.equal(s.otpField(d.getElementById("hint")), true);
  assert.equal(s.otpField(d.getElementById("user")), false);
  assert.equal(s.otpField(d.getElementById("short")), false, "maxlength 4 is rejected");
});

test("submitCandidate requires one visible submit with a localized sign-in label and POST", () => {
  const p = page(`
    <form id="de" action="/login" method="post"><input type="text" name="u"><input id="pw1" type="password"><button id="b1" type="submit">Anmelden</button></form>
    <form id="verbose" action="/login" method="post"><input id="pw2" type="password"><button type="submit">Sign in now</button></form>
    <form id="get" action="/login" method="get"><input id="pw3" type="password"><button type="submit">Σύνδεση</button></form>
    <form id="two" action="/login" method="post"><input id="pw4" type="password"><button type="submit">Log in</button><button type="submit">Login</button></form>`);
  const { document: d, S } = p;
  const s = S();
  const ctx = id => s.snapshot(d.getElementById(id));
  assert.equal(s.submitCandidate(ctx("pw1")), d.getElementById("b1"), "German label accepted");
  assert.equal(s.submitCandidate(ctx("pw2")), null, "label must match exactly, not contain");
  assert.equal(s.submitCandidate(ctx("pw3")), null, "GET forms never auto-submit");
  assert.equal(s.submitCandidate(ctx("pw4")), null, "two submit buttons are ambiguous");
  assert.equal(s.isSignInLabel("  Zaloguj   się "), true);
});

test("queryAll walks nested open shadow roots and onTop sees through shadow hosts", () => {
  const p = page(`<div id="outer"></div><div id="overlay"></div>`);
  const { document: d, S, openShadow, setRect } = p;
  const outerRoot = openShadow(d.getElementById("outer"), `<div id="inner"></div><input id="shallow" type="text">`);
  const innerRoot = openShadow(outerRoot.getElementById("inner"), `<form action="/s" method="post"><input id="deep" type="password"></form>`);
  const s = S();
  const inputs = s.queryAll("input");
  assert.equal(inputs.map(i => i.id).join(","), "shallow,deep");
  assert.equal(s.shadowRoots(d).length, 2);
  const deep = innerRoot.getElementById("deep");
  assert.equal(s.visible(deep), true);
  assert.equal(s.onTop(deep), true, "hit test descends through the host chain");
  assert.equal(s.currentPassword(deep), true);
  const ctx = s.snapshot(deep);
  assert.equal(ctx.form, deep.form);
  setRect(d.getElementById("overlay"), { left: 0, top: 0, width: 1024, height: 768 });
  assert.equal(s.onTop(deep), false, "a document-level overlay still covers shadow content");
  // Closed roots are never traversed.
  const closedHost = d.createElement("div"); d.body.append(closedHost);
  closedHost.attachShadow({ mode: "closed" }).innerHTML = `<input id="secret" type="password">`;
  assert.equal(s.queryAll("input").some(i => i.id === "secret"), false);
});
