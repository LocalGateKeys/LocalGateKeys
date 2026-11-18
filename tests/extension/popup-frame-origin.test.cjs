/* Final review L7 (2026-11-15): the popup's "Why no icon?" note names another
 * site's frame only when that frame's content script reports a password
 * field, and gives no advice to open it. jsdom + a chrome mock. */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const { JSDOM } = require("jsdom");
const { EXT } = require("./helpers.cjs");

async function popupWith(frames, passwordFrames) {
  const dom = new JSDOM(`<ul id="site-logins" hidden></ul><p id="site-logins-empty"></p><p id="logins-note"></p>
    <button id="popup-only" role="switch"></button><p id="popup-only-hint"></p><p id="frame-origin" hidden></p>`);
  const asked = [];
  const chrome = {
    i18n: { getMessage: require("./i18n-stub.cjs").getMessage },
    runtime: { id: "testextension", sendMessage: async () => ({ ok: false, error: "unsupported" }), getManifest: () => ({ version: "0.4.12" }) },
    storage: { local: { get: async d => d, set: async () => {} } },
    tabs: {
      query: async () => [{ id: 5, url: "https://shop.example.test/checkout" }],
      sendMessage: async (tabId, message, options) => {
        asked.push({ tabId, message, frameId: options?.frameId });
        if (message.command !== "has_password_field") return null;
        return { ok: true, password: passwordFrames.includes(options.frameId) };
      },
    },
    webNavigation: { getAllFrames: async () => frames },
  };
  const context = vm.createContext({ chrome, document: dom.window.document, URL, Promise, setTimeout, clearTimeout, console });
  vm.runInContext(fs.readFileSync(path.join(EXT, "api.js"), "utf8"), context);
  vm.runInContext(fs.readFileSync(path.join(EXT, "popup-logins.js"), "utf8"), context);
  for (let i = 0; i < 20; i++) await new Promise(r => setImmediate(r));
  return { line: dom.window.document.getElementById("frame-origin"), asked };
}

const FRAMES = [
  { frameId: 0, url: "https://shop.example.test/checkout", errorOccurred: false },
  { frameId: 3, url: "https://ads.example.net/slot", errorOccurred: false },
  { frameId: 4, url: "https://login.bank.example/frame", errorOccurred: false },
  { frameId: 5, url: "https://shop.example.test/inner", errorOccurred: false },
];

test("L7: only a cross-origin frame that holds a password field is named, with no advice to open it", async () => {
  const { line, asked } = await popupWith(FRAMES, [4]);
  assert.equal(line.hidden, false);
  assert.match(line.textContent, /login\.bank\.example/);
  assert.doesNotMatch(line.textContent, /ads\.example\.net/);
  assert.doesNotMatch(line.textContent, /directly/);
  assert.deepEqual(asked.map(a => a.frameId).sort(), [3, 4], "same-origin frames and the top frame are not asked");
});

test("L7: ad and embed frames without a password field are not named at all", async () => {
  const { line } = await popupWith(FRAMES, []);
  assert.equal(line.hidden, true);
  assert.equal(line.textContent, "");
});
