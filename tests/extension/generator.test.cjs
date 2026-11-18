/* Popup password generator (browser-extension/generator.js): option bounds,
 * character groups, look-alikes and passphrases from the bundled word list. */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const EXT = path.join(__dirname, "../../browser-extension");
const ctx = vm.createContext({ crypto: globalThis.crypto, Uint32Array, Array, Object, Number, String, Math, Set, RangeError, Error });
vm.runInContext(fs.readFileSync(path.join(EXT, "generator.js"), "utf8"), ctx);
const G = vm.runInContext("globalThis.LGKGenerator", ctx);
const WORDS = G.parseWords(fs.readFileSync(path.join(EXT, "wordlist.txt"), "utf8"));

test("normalize clamps values and drops unknown ones", () => {
  const o = G.normalize({ mode: "evil", length: 9999, words: 1, separator: "x", symbols: "yes" });
  assert.equal(o.mode, "password");
  assert.equal(o.length, 128);
  assert.equal(o.words, 3);
  assert.equal(o.separator, "dash");
  assert.equal(o.symbols, true);
  assert.equal(G.normalize(null).length, 20);
});

test("password honours length, groups and look-alikes", () => {
  for (let i = 0; i < 200; i++) {
    const v = G.password({ length: 12, symbols: false });
    assert.equal(v.length, 12);
    assert.match(v, /[a-z]/); assert.match(v, /[A-Z]/); assert.match(v, /[0-9]/);
    assert.doesNotMatch(v, /[^a-zA-Z0-9]/);
    assert.doesNotMatch(v, /[Il1O0o]/);
  }
  assert.match(G.password({ length: 8, lowercase: false, uppercase: false, symbols: false }), /^[2-9]{8}$/);
  assert.throws(() => G.password({ lowercase: false, uppercase: false, digits: false, symbols: false }), /no_group/);
  assert.match(G.password({ length: 40, avoidAmbiguous: false, uppercase: false, digits: false, symbols: false }), /^[a-z]{40}$/);
});

test("passphrase uses the word list, separator, capitals and number", () => {
  assert.ok(WORDS.length >= 5000);
  const v = G.passphrase({ mode: "passphrase", words: 5, separator: "dot", capitalize: true, appendNumber: true }, WORDS);
  const m = /^(.+)(\d{2})$/.exec(v);
  assert.ok(m, v);
  const parts = m[1].split(".");
  assert.equal(parts.length, 5);
  for (const w of parts) { assert.match(w, /^[A-Z]/); assert.ok(WORDS.includes(w.toLowerCase()), w); }
  assert.throws(() => G.passphrase({}, []), /no_words/);
});

test("randomBelow stays in range", () => {
  for (let i = 0; i < 500; i++) { const n = G.randomBelow(7); assert.ok(n >= 0 && n < 7); }
});
