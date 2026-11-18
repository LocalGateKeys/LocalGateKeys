"use strict";
// Lint gate for the Firefox Add-ons (AMO) upload: builds the Firefox variant
// and runs Mozilla's web-ext lint on it. Errors block an AMO submission.
// Skips when web-ext is not installed (npm ci installs it as a devDependency).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..", "..");
const WEB_EXT = path.join(ROOT, "node_modules", "web-ext", "bin", "web-ext.js");

test("Firefox build passes web-ext lint with 0 errors", { timeout: 300000 }, t => {
  if (!fs.existsSync(WEB_EXT)) {
    t.skip("web-ext not installed; run npm ci");
    return;
  }
  // Same command as `npm run lint:firefox`; npm appends the extra flags to web-ext lint.
  const lint = spawnSync("npm", ["run", "--silent", "lint:firefox", "--", "--output", "json", "--no-input"], { encoding: "utf8", cwd: ROOT, shell: process.platform === "win32" });
  assert.equal(lint.error, undefined, String(lint.error));
  const start = lint.stdout.indexOf("{");
  assert.ok(start >= 0, `no JSON from web-ext lint: ${lint.stdout}${lint.stderr}`);
  const report = JSON.parse(lint.stdout.slice(start));
  const errors = report.errors.map(e => `${e.code} ${e.file || ""}: ${e.message}`);
  assert.deepEqual(errors, []);
});
