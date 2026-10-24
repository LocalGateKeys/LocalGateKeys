#!/usr/bin/env node
"use strict";
// Produces a Firefox MV3 build of the extension from the Chromium manifest.
//
// Why a variant: Chrome (minimum_chrome_version 111) rejects a manifest that
// carries both background.service_worker and background.scripts, while
// Firefox MV3 runs background.scripts only. Everything else is shared.
//
// Usage: node browser-extension/build-firefox-manifest.cjs [outDir]
//        default outDir: build/firefox-extension (gitignored via build/)
const fs = require("node:fs");
const path = require("node:path");

const SOURCE_DIR = __dirname;
const PASSKEY_SCRIPTS = new Set(["webauthn-page.js", "webauthn-bridge.js"]);
const SKIP = new Set([path.basename(__filename), "manifest.json", ...PASSKEY_SCRIPTS]);
// Build tooling (build-*.cjs) never ships inside the add-on.
const isBuildScript = name => /^build-.*\.cjs$/.test(name);

function firefoxManifest(chromeManifest) {
  const m = JSON.parse(JSON.stringify(chromeManifest));
  // Firefox uses browser_specific_settings.gecko.id instead of the Chrome key.
  delete m.key;
  delete m.minimum_chrome_version;
  if (!m.browser_specific_settings?.gecko?.id) throw new Error("manifest.json lacks browser_specific_settings.gecko.id");
  // No service workers for extension backgrounds; load the shim first.
  const worker = m.background?.service_worker;
  if (!worker) throw new Error("manifest.json lacks background.service_worker");
  m.background = { scripts: ["api.js", worker] };
  // Firefox has no favicon permission / _favicon endpoint. background.js then
  // sends no site_icon and the desktop app uses its neutral icon.
  m.permissions = (m.permissions || []).filter(p => p !== "favicon");
  // Passkeys are Chromium-only in this release: drop the MAIN-world wrapper
  // and its bridge, so Firefox pages keep their native WebAuthn untouched.
  m.content_scripts = (m.content_scripts || []).filter(cs => !(cs.js || []).some(f => PASSKEY_SCRIPTS.has(f)));
  // No web-accessible resources: the in-page icons are inline SVG, and a
  // static moz-extension:// URL would let pages fingerprint the extension.
  delete m.web_accessible_resources;
  return m;
}

function build(outDir) {
  const chromeManifest = JSON.parse(fs.readFileSync(path.join(SOURCE_DIR, "manifest.json"), "utf8"));
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });
  for (const entry of fs.readdirSync(SOURCE_DIR, { withFileTypes: true })) {
    if (SKIP.has(entry.name) || isBuildScript(entry.name)) continue;
    fs.cpSync(path.join(SOURCE_DIR, entry.name), path.join(outDir, entry.name), { recursive: true });
  }
  fs.writeFileSync(path.join(outDir, "manifest.json"), JSON.stringify(firefoxManifest(chromeManifest), null, 2) + "\n");
  return outDir;
}

module.exports = { firefoxManifest, build, isBuildScript };

if (require.main === module) {
  const outDir = path.resolve(process.argv[2] || path.join(SOURCE_DIR, "..", "build", "firefox-extension"));
  console.log(`Firefox build written to ${build(outDir)}`);
}
