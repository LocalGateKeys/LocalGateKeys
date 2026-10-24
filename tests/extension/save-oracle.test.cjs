"use strict";
// Audit M-3 / review R-5: the save prompt is no password-guessing oracle.
// A same-origin script watching <html> with a MutationObserver must see the
// same DOM changes after a right and after a wrong password guess.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createPage } = require("./helpers.cjs");

const LOGIN_FORM = `<form id="login" action="/session" method="post">
  <input id="user" type="text" name="username" autocomplete="username">
  <input id="pw" type="password" name="password">
  <button id="submit" type="submit">Sign in</button>
</form>`;
const STORED = { alice: "correct-horse" };

// The desktop broker as the extension sees it. `legacy` replays the statuses an
// app from before the fix still sends for a stored capture ("exact" /
// "password_changed"); the current broker answers "exists" for both.
// `oracle` is the broker before the fix, which kept no capture (so showed no
// prompt) for a matching password: the observer below must catch that.
function broker(state, { legacy = false, oracle = false } = {}) {
  return async request => {
    switch (request.type) {
      case "capture_browser": {
        if (oracle && STORED[request.username] === request.password) return { ok: true, stored: false, status: "exact" };
        state.capture = { username: request.username, password: request.password };
        return { ok: true, stored: true, pending_token: "tok-1", token: "tok-1", status: classify(state.capture, legacy) };
      }
      case "pending_browser":
        if (!state.capture) return { ok: true, pending: false };
        return { ok: true, pending: true, pending_token: "tok-1", token: "tok-1", username: state.capture.username,
          status: classify(state.capture, legacy), age_ms: 0 };
      case "check_browser":
        return { ok: true, locked: false, match: false, prompt: true,
          status: classify({ username: request.username, password: request.password }, legacy) };
      default: return { ok: true };
    }
  };
}
function classify({ username, password }, legacy) {
  if (!(username in STORED)) return "new";
  if (!legacy) return "exists";
  return STORED[username] === password ? "exact" : "password_changed";
}

// Everything a page observer gets, with the per-page random attribute name
// normalised (it is random by design and differs between any two pages).
function describe(records) {
  const name = n => (n ? n.replace(/^data-[a-z]{12}$/, "data-<random>") : n);
  const node = n => (n.nodeType === 1 ? `${n.tagName}[${n.getAttributeNames().map(name).sort().join(",")}]` : n.nodeName);
  return records.map(r => ({
    type: r.type, target: node(r.target), attribute: name(r.attributeName),
    added: [...r.addedNodes].map(node), removed: [...r.removedNodes].map(node),
  }));
}
function snapshot(document) {
  return document.documentElement.outerHTML.replace(/data-[a-z]{12}(?==)/g, "data-<random>");
}

async function guess(password, options) {
  const state = {};
  const p = createPage({ html: LOGIN_FORM, respond: broker(state, options) });
  p.load();
  await p.tick();
  const records = [];
  const observer = new p.window.MutationObserver(list => records.push(...list));
  observer.observe(p.document.documentElement, { subtree: true, childList: true, attributes: true, characterData: true });
  p.document.getElementById("user").value = "alice";
  p.document.getElementById("pw").value = password;
  p.trusted(p.document.getElementById("login"), "submit", {}, p.impls.SubmitEventImpl);
  await p.tick(4);
  p.document.getElementById("login").remove();
  p.clock.now += 1000;
  await p.command("check_pending_save");
  await p.sleep(140);
  await p.tick(4);
  records.push(...observer.takeRecords());
  observer.disconnect();
  return { p, state, records: describe(records), html: snapshot(p.document), panel: p.panelText() };
}

for (const legacy of [false, true]) {
  const label = legacy ? "an app from before the fix" : "the current app";
  test(`save prompt: identical page-visible DOM for a right and a wrong password (${label})`, async () => {
    const right = await guess("correct-horse", { legacy });
    const wrong = await guess("battery-staple", { legacy });
    assert.equal(right.state.capture.password, "correct-horse", "the guess reached the broker");
    assert.ok(right.records.some(r => r.added.some(n => n.startsWith("DIV["))), "a panel host was added");
    assert.deepEqual(right.records, wrong.records);
    assert.equal(right.html, wrong.html);
    // The closed-shadow content is the same too: one neutral prompt.
    assert.equal(right.panel, wrong.panel);
    assert.match(right.panel, /Save \/ update in LocalGateKeys\?/);
    assert.doesNotMatch(right.panel, /Update saved password/);
  });
}

test("save prompt: the explicit save panel is the same for a right and a wrong password", async () => {
  const run = async password => {
    const p = createPage({ html: LOGIN_FORM, respond: broker({}, { legacy: true }) });
    p.load();
    await p.tick();
    p.document.getElementById("user").value = "alice";
    p.document.getElementById("pw").value = password;
    await p.command("save_current");
    await p.tick(4);
    return p.panelText();
  };
  const right = await run("correct-horse"), wrong = await run("battery-staple");
  assert.equal(right, wrong);
  assert.match(right, /Save \/ update in LocalGateKeys\?/);
});

test("save prompt: the observer used above does tell the pre-fix broker's answers apart", async () => {
  const right = await guess("correct-horse", { legacy: true, oracle: true });
  const wrong = await guess("battery-staple", { legacy: true, oracle: true });
  assert.notDeepEqual(right.records, wrong.records, "a right guess showed no panel before the fix");
});
