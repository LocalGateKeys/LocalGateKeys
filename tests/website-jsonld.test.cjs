/* Finding L3 (2026-11-15 final review): the built site's JSON-LD carries the
 * filled price, never a {{PLACEHOLDER}}. Reads website/public as built by
 * website/build.py (which now also fails on any unsubstituted placeholder). */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const PUBLIC = path.join(__dirname, "..", "website", "public");

function htmlFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...htmlFiles(full));
    else if (entry.name.endsWith(".html")) out.push(full);
  }
  return out;
}

test("website JSON-LD: no placeholder survives and the Pro price is filled", { skip: !fs.existsSync(PUBLIC) && "website/public not built" }, () => {
  const leftovers = [];
  let priced = 0;
  for (const file of htmlFiles(PUBLIC)) {
    const text = fs.readFileSync(file, "utf8");
    for (const m of text.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)) {
      if (/\{\{[A-Z0-9_]+\}\}/.test(m[1])) leftovers.push(path.relative(PUBLIC, file));
      JSON.parse(m[1]);
      if (/"price":"\d+(\.\d{2})?"/.test(m[1]) && /US\$\d/.test(m[1])) priced += 1;
    }
  }
  assert.deepEqual(leftovers, []);
  assert.ok(priced > 0, "some page names the filled price in its JSON-LD description");
});
