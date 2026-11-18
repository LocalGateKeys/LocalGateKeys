/* Lookalike-domain classifier (browser-extension/lookalike.js). The vectors
 * in tests/vectors/lookalike/cases.json are shared with tests/test_lookalike.py. */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const EXT = path.join(__dirname, "../../browser-extension");
const VECTORS = JSON.parse(fs.readFileSync(path.join(__dirname, "../vectors/lookalike/cases.json"), "utf8"));
const PSL_TEXT = fs.readFileSync(path.join(EXT, "psl-min.json"), "utf8");

function load() {
  const ctx = vm.createContext({ URL });
  vm.runInContext(fs.readFileSync(path.join(EXT, "lookalike.js"), "utf8"), ctx);
  return vm.runInContext("globalThis.LGKLookalike", ctx);
}

const L = load();
L.setRules(JSON.parse(PSL_TEXT));

test("vectors cover every kind", () => {
  assert.ok(VECTORS.cases.length >= 40);
  assert.deepEqual(new Set(VECTORS.cases.map(c => c.kind)), new Set(["exact", "related", "lookalike", "unknown"]));
});

for (const c of VECTORS.cases) {
  test(`vector: ${c.name}`, () => {
    const v = L.classify(c.origin, c.saved);
    assert.deepEqual({ kind: v.kind, matched: v.matched, reason: v.reason },
      { kind: c.kind, matched: c.matched, reason: c.reason });
  });
}

test("cross-check corpus: every pair and list agrees with Python", () => {
  const X = JSON.parse(fs.readFileSync(path.join(__dirname, "../vectors/lookalike/crosscheck.json"), "utf8"));
  assert.ok(X.pairs.length >= 5000);
  // Known differences from Python (scripts/build_lookalike_crosscheck.py JS_DIFFERS): they must still differ.
  const differs = new Set(X.js_differs);
  const failures = [];
  const differed = new Set();
  const check = (label, v, kind, matched, reason) => {
    const origin = label.slice(0, label.lastIndexOf(" vs "));
    if (differs.has(origin)) {
      if (v.kind !== kind || v.reason !== reason) differed.add(origin);
      return;
    }
    const want = { kind, matched: matched < 0 ? null : X.saved[matched], reason };
    const got = { kind: v.kind, matched: v.matched, reason: v.reason };
    if (JSON.stringify(got) !== JSON.stringify(want)) failures.push(`${label}: want ${JSON.stringify(want)} got ${JSON.stringify(got)}`);
  };
  for (const [o, s, kind, matched, reason] of X.pairs) {
    check(`${X.origins[o]} vs ${X.saved[s]}`, L.classify(X.origins[o], [X.saved[s]]), kind, matched, reason);
  }
  for (const [o, kind, matched, reason] of X.lists) {
    check(`${X.origins[o]} vs all`, L.classify(X.origins[o], X.saved), kind, matched, reason);
  }
  assert.deepEqual(failures, []);
  // Node's URL/IDNA parsing changes between versions (Node 26 agrees with Python on the Hebrew mixed-script hosts,
  // Node 22 does not), so a listed origin may differ or agree; it only must not be a difference nobody listed.
  assert.ok([...differed].every((o) => differs.has(o)));
});

test("verdict is frozen and has exactly kind, matched, reason", () => {
  const v = L.classify("https://example.com", ["https://example.com"]);
  assert.ok(Object.isFrozen(v));
  assert.deepEqual(Object.keys(v).sort(), ["kind", "matched", "reason"]);
});

test("non-string and non-array saved input is tolerated", () => {
  assert.equal(L.classify("https://example.com", null).kind, "unknown");
  assert.equal(L.classify("https://example.com", [null, 42, "https://example.com"]).kind, "exact");
  assert.equal(L.classify(undefined, ["https://example.com"]).reason, "invalid-origin");
});

test("setRules refuses a malformed rule set", () => {
  const fresh = load();
  assert.throws(() => fresh.setRules({ normal: [] }), /psl/i);
  assert.throws(() => fresh.setRules(null), /psl/i);
});

test("punycode decoder matches known labels", () => {
  assert.equal(L.punycodeDecode("pple-43d"), "аpple");
  assert.equal(L.punycodeDecode("80ak6aa92e"), "аррӏе");
  assert.equal(L.punycodeDecode("bcher-kva"), "bücher");
  assert.throws(() => L.punycodeDecode("a-é"));
});

test("Damerau-Levenshtein (optimal string alignment)", () => {
  assert.equal(L.osaDistance("example", "exmaple"), 1);
  assert.equal(L.osaDistance("example", "exmapel"), 2);
  assert.equal(L.osaDistance("example", "axumplo"), 3);
  assert.equal(L.osaDistance("", "abc"), 3);
});

test("psl-min.json stays small enough for the extension", () => {
  assert.ok(Buffer.byteLength(PSL_TEXT) < 160000);
});

test("module has no network or extension API access", () => {
  const src = fs.readFileSync(path.join(EXT, "lookalike.js"), "utf8");
  assert.doesNotMatch(src, /\bfetch\s*\(|XMLHttpRequest|WebSocket|chrome\.|browser\./);
});
