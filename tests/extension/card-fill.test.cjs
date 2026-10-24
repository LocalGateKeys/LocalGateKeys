/* Card fill (card_protocol 1) in jsdom: payment-form detection, approval
 * checklist defaults, split / single expiry formatting, cross-origin refusal,
 * CVV opt-in, no submit, and value clearing. No network, no real broker. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createPage } = require("./helpers.cjs");

const NONCE_BEGIN = "1".repeat(32), NONCE_APPROVE = "2".repeat(32);
const ALL_TOKENS = ["cc-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type"];
const LABELS = { "cc-name": "Cardholder name", "cc-number": "Card number", "cc-exp": "Expiry (MM/YYYY)", "cc-exp-month": "Expiry month", "cc-exp-year": "Expiry year", "cc-csc": "Security code (CVV)", "cc-type": "Card brand" };
const VALUES = { "cc-name": "Alice Example", "cc-number": "4111111111111111", "cc-exp": "03/2027", "cc-exp-month": "03", "cc-exp-year": "2027", "cc-csc": "123", "cc-type": "Visa" };
function choice(overrides = {}) {
  const fields = {};
  for (const token of ALL_TOKENS) fields[token] = { label: LABELS[token], protected: token === "cc-number" || token === "cc-csc", present: true };
  return { entry_id: "card-1", title: "Personal Visa", favorite: false, revision: 7, brand: "Visa", last4: "1111", fields, ...overrides };
}
function cardResponder(state = {}, { choices = [choice()] } = {}) {
  state.releases = []; state.approvals = [];
  return async request => {
    switch (request.type) {
      case "begin_card_browser": return { ok: true, card_protocol: 1, choices, origin: request.origin, session_id: "s1", profile: { name: "Home" }, gesture_nonce: NONCE_BEGIN, gesture_expires_in: 30 };
      case "approve_card_browser": state.approvals.push(request); return { ok: true, card_protocol: 1, approval: "appr-1", entry_id: request.entry_id, revision: request.revision, fields: [...request.fields], session_id: "s1", gesture_nonce: NONCE_APPROVE, gesture_expires_in: 30 };
      case "release_card_browser": {
        state.releases.push(request);
        const values = {}; for (const f of request.fields) values[f] = VALUES[f];
        const reply = { ok: true, card_protocol: 1, entry_id: request.entry_id, revision: request.revision, fields: [...request.fields], values };
        state.lastRelease = reply; state.lastValues = values;
        return reply;
      }
      case "cancel_card_browser": state.cancelled = request.approval; return { ok: true };
      case "ping": return { ok: true, version: "0.3.3", locked: false };
      default: return null;
    }
  };
}
function panelButtons(p) { const root = p.shadows.get(p.panelHost()); return root ? Array.from(root.querySelectorAll("button")) : []; }
function clickPanelButton(p, text) {
  const button = panelButtons(p).find(b => b.textContent.includes(text));
  if (!button) throw new Error(`no panel button containing "${text}" in: ${panelButtons(p).map(b => b.textContent).join(" | ")}`);
  p.trusted(button, "click", { composed: true }, p.impls.MouseEventImpl);
}
const checks = p => panelButtons(p).filter(b => b.getAttribute("role") === "checkbox").map(b => ({ token: b.dataset.token, checked: b.getAttribute("aria-checked") === "true" }));
async function loaded(options) { const p = createPage(options); p.load(); await p.tick(); return p; }

const AUTOCOMPLETE_FORM = `<form id="pay" action="/charge" method="post">
  <input id="name" type="text" name="holder" autocomplete="cc-name">
  <input id="number" type="text" name="pan" autocomplete="cc-number">
  <input id="exp" type="text" name="expiry" autocomplete="cc-exp" placeholder="MM/YY">
  <input id="cvc" type="text" name="code" autocomplete="cc-csc">
  <button id="submit" type="submit">Pay now</button>
</form>`;
const HEURISTIC_FORM = `<form id="pay" action="/charge" method="post" autocomplete="off">
  <input id="number" type="tel" name="cardNumber">
  <select id="month" name="exp_month"><option value="">MM</option><option value="1">01</option><option value="3">03</option><option value="12">12</option></select>
  <input id="year" type="text" name="exp_year" maxlength="2" placeholder="YY">
  <input id="cvv" type="text" name="cvv" maxlength="4">
  <button type="submit">Pay</button>
</form>`;

test("detection: autocomplete cc-* tokens put one card button on the card-number field; card controls get no identity or OTP buttons", async () => {
  const p = await loaded({ html: AUTOCOMPLETE_FORM });
  assert.equal(p.cardIcons().length, 1);
  assert.equal(p.otpIcons().length, 0, "the security-code field is not a 2FA field");
  assert.equal(p.identityIcons().length, 0, "the cardholder name is not an identity field");
  assert.equal(p.fieldIcons().length, 0);
  const S = p.S(); const d = p.document;
  assert.deepEqual(Object.keys(S.cardFieldMap(d.getElementById("pay"))).sort(), ["cc-csc", "cc-exp", "cc-name", "cc-number"]);
});

test("detection: name/id heuristics find number, split expiry and CVV when autocomplete is absent", async () => {
  const p = await loaded({ html: HEURISTIC_FORM });
  assert.equal(p.cardIcons().length, 1);
  assert.equal(p.otpIcons().length, 0);
  const S = p.S(); const d = p.document;
  const map = S.cardFieldMap(d.getElementById("pay"));
  assert.equal(map["cc-number"][0], d.getElementById("number"));
  assert.equal(map["cc-exp-month"][0], d.getElementById("month"));
  assert.equal(map["cc-exp-year"][0], d.getElementById("year"));
  assert.equal(map["cc-csc"][0], d.getElementById("cvv"));
  assert.equal(map["cc-exp"], undefined, "month/year win over the generic expiry pattern");
});

test("detection: heuristics never fire without a card-number-like field, and explicit non-card autocomplete opts a control out", async () => {
  const p = await loaded({ html: `<form action="/x" method="post"><input id="exp" name="expiry"><input id="cvv" name="cvv"><input id="n" type="text" name="card_number" autocomplete="username"></form>
    <form id="phone" action="/y" method="post"><input name="phone_number"><input name="account_no"></form>` });
  assert.equal(p.cardIcons().length, 0);
  const S = p.S(); const d = p.document;
  assert.equal(S.cardToken(d.getElementById("exp"), true), "cc-exp", "the pattern itself matches");
  assert.deepEqual(Object.keys(S.cardFieldMap(d.getElementById("exp").form)), [], "but the scope has no card number, so nothing is a card field");
  assert.deepEqual(Object.keys(S.cardFieldMap(d.getElementById("phone"))), []);
});

test("fill_card: the approval checklist offers the tokens present on the page, ticks all but the CVV, and releases only the ticked ones", async () => {
  const state = {};
  const p = await loaded({ html: AUTOCOMPLETE_FORM, respond: cardResponder(state) });
  let submitted = 0;
  p.document.getElementById("pay").addEventListener("submit", () => submitted++);
  const reply = await p.command("fill_card");
  assert.equal(reply.ok, true);
  await p.tick(6);
  assert.equal(p.sent("begin_card_browser").length, 1);
  assert.equal(p.sent("begin_card_browser")[0].card_protocol, 1);
  assert.equal(p.sent("begin_card_browser")[0].user_gesture, true);
  assert.match(p.panelText(), /Choose card fields/);
  assert.match(p.panelText(), /Personal Visa/);
  assert.match(p.panelText(), /•••• 1111/);
  assert.deepEqual(checks(p), [
    { token: "cc-name", checked: true }, { token: "cc-number", checked: true }, { token: "cc-exp", checked: true }, { token: "cc-csc", checked: false },
  ]);
  clickPanelButton(p, "Review and approve");
  await p.tick(10);
  assert.equal(state.approvals.length, 1);
  assert.deepEqual([...state.approvals[0].fields], ["cc-name", "cc-number", "cc-exp"]);
  assert.equal(state.approvals[0].session_id, "s1");
  assert.equal(state.approvals[0].revision, 7);
  assert.equal(state.releases.length, 1);
  assert.deepEqual([...state.releases[0].fields], ["cc-name", "cc-number", "cc-exp"]);
  assert.equal(state.releases[0].approval, "appr-1");
  assert.equal(state.releases[0].gesture_nonce, NONCE_APPROVE, "release presents the nonce minted by approve_card_browser");
  const d = p.document;
  assert.equal(d.getElementById("name").value, "Alice Example");
  assert.equal(d.getElementById("number").value, "4111111111111111");
  assert.equal(d.getElementById("exp").value, "03/27", "MM/YY placeholder shortens the broker's MM/YYYY");
  assert.equal(d.getElementById("cvc").value, "", "CVV was not approved, so it is never filled");
  assert.equal(submitted, 0, "nothing is submitted");
  assert.equal(p.panelVisible(), false);
  assert.deepEqual({ ...state.lastValues }, { "cc-name": "", "cc-number": "", "cc-exp": "" }, "released values are blanked after the fill");
  assert.equal(state.lastRelease.values, null, "and the reply no longer references them");
});

test("fill_card: ticking the CVV releases and fills it", async () => {
  const state = {};
  const p = await loaded({ html: AUTOCOMPLETE_FORM, respond: cardResponder(state) });
  await p.command("fill_card");
  await p.tick(6);
  clickPanelButton(p, "Security code");
  assert.equal(checks(p).find(c => c.token === "cc-csc").checked, true);
  clickPanelButton(p, "Review and approve");
  await p.tick(10);
  assert.deepEqual([...state.releases[0].fields], ["cc-name", "cc-number", "cc-exp", "cc-csc"]);
  assert.equal(p.document.getElementById("cvc").value, "123");
});

test("fill_card: split expiry fills a month select and a two-digit year input; the broker's MM/YYYY is never written raw", async () => {
  const state = {};
  const p = await loaded({ html: HEURISTIC_FORM, respond: cardResponder(state) });
  await p.command("fill_card");
  await p.tick(6);
  assert.deepEqual(checks(p).map(c => c.token), ["cc-number", "cc-exp-month", "cc-exp-year", "cc-csc"]);
  clickPanelButton(p, "Review and approve");
  await p.tick(10);
  const d = p.document;
  assert.equal(d.getElementById("number").value, "4111111111111111");
  assert.equal(d.getElementById("month").value, "3", "option matched by numeric value");
  assert.equal(d.getElementById("year").value, "27", "maxlength 2 / YY placeholder");
  assert.equal(d.getElementById("cvv").value, "");
});

test("expiry formatting follows the page field's hints", async () => {
  const p = await loaded({ html: `<form action="/x" method="post" id="f">
    <input id="a" placeholder="MM/YYYY"><input id="b" placeholder="MM / YY"><input id="c" maxlength="4"><input id="d" maxlength="7"><input id="e"><input id="g" placeholder="MM-YY"><input id="h" maxlength="2"><input id="i" placeholder="YYYY">
  </form>` });
  const S = p.S(); const d = p.document; const by = id => d.getElementById(id);
  assert.equal(S.formatCardExpiry("03/2027", by("a")), "03/2027");
  assert.equal(S.formatCardExpiry("03/2027", by("b")), "03/27");
  assert.equal(S.formatCardExpiry("3/2027", by("c")), "0327");
  assert.equal(S.formatCardExpiry("03/2027", by("d")), "03/2027");
  assert.equal(S.formatCardExpiry("03/2027", by("e")), "03/27", "no hint: MM/YY is the web default");
  assert.equal(S.formatCardExpiry("03/2027", by("g")), "03-27");
  assert.equal(S.formatCardExpiry("garbage", by("e")), null);
  assert.equal(S.formatCardYear("2027", by("h")), "27");
  assert.equal(S.formatCardYear("27", by("i")), "2027");
  assert.equal(S.formatCardMonth("3"), "03");
});

test("fill_card refuses a payment form that posts to another origin before any native call", async () => {
  const p = await loaded({ html: AUTOCOMPLETE_FORM.replace('action="/charge"', 'action="https://evil.test/charge"'), respond: cardResponder() });
  const reply = await p.command("fill_card");
  assert.equal(reply.ok, true, "the button exists; the refusal is shown in the panel");
  await p.tick(4);
  assert.equal(p.sent("begin_card_browser").length, 0);
  assert.match(p.panelText(), /another origin/);
  assert.equal(p.document.getElementById("number").value, "");
});

test("fill_card: a release that contains an unapproved field is discarded and nothing is filled", async () => {
  const state = {};
  const inner = cardResponder(state);
  const p = await loaded({ html: AUTOCOMPLETE_FORM, respond: async r => {
    if (r.type !== "release_card_browser") return inner(r);
    const reply = await inner(r);
    reply.values["cc-csc"] = "999"; // broker (or a tampered bridge) returned more than approved
    return reply;
  } });
  await p.command("fill_card");
  await p.tick(6);
  clickPanelButton(p, "Review and approve");
  await p.tick(10);
  const d = p.document;
  assert.equal(d.getElementById("number").value, "");
  assert.equal(d.getElementById("cvc").value, "");
  assert.match(p.panelText(), /unapproved/);
});

test("fill_card: two cards show a picker with brand and last four; Cancel after approval revokes it", async () => {
  const state = {};
  const second = choice({ entry_id: "card-2", title: "Work Amex", brand: "Amex", last4: "0005", favorite: true });
  const p = await loaded({ html: AUTOCOMPLETE_FORM, respond: cardResponder(state, { choices: [second, choice()] }) });
  await p.command("fill_card");
  await p.tick(6);
  assert.match(p.panelText(), /Choose a card/);
  assert.match(p.panelText(), /Amex •••• 0005/);
  assert.match(p.panelText(), /Visa •••• 1111/);
  clickPanelButton(p, "Work Amex");
  assert.match(p.panelText(), /Work Amex/);
  assert.equal(p.sent("approve_card_browser").length, 0);
  clickPanelButton(p, "Cancel");
  await p.tick(4);
  assert.equal(p.panelVisible(), false);
  assert.equal(p.sent("begin_card_browser").length, 1);
  assert.equal(p.sent("release_card_browser").length, 0);
});

test("fill_card with no payment form answers card_form_not_found and card_not_found from the broker is shown", async () => {
  const p = await loaded({ html: `<form action="/x" method="post"><input name="q"></form>`, respond: cardResponder() });
  const reply = await p.command("fill_card");
  assert.deepEqual({ ...reply }, { ok: false, error: "card_form_not_found" });
  const q = await loaded({ html: AUTOCOMPLETE_FORM, respond: async r => r.type === "begin_card_browser" ? { ok: false, error: "card_not_found" } : null });
  await q.command("fill_card");
  await q.tick(6);
  assert.match(q.panelText(), /No payment card is saved/);
});
