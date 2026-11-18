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
const SKIP = new Set([path.basename(__filename), "manifest.json"]);
// Build tooling (build-*.cjs) never ships inside the add-on.
const isBuildScript = name => /^build-.*\.cjs$/.test(name);

function firefoxManifest(chromeManifest) {
  const m = JSON.parse(JSON.stringify(chromeManifest));
  // Firefox uses browser_specific_settings.gecko.id instead of the Chrome key.
  delete m.key;
  delete m.minimum_chrome_version;
  if (!m.browser_specific_settings?.gecko?.id) throw new Error("manifest.json lacks browser_specific_settings.gecko.id");
  // No service workers for extension backgrounds; load the shim and the
  // lookalike classifier (Chromium pulls both in with importScripts) first.
  const worker = m.background?.service_worker;
  if (!worker) throw new Error("manifest.json lacks background.service_worker");
  m.background = { scripts: ["api.js", "lookalike.js", worker] };
  // Firefox has no favicon permission / _favicon endpoint. background.js then
  // sends no site_icon and the desktop app uses its neutral icon.
  m.permissions = (m.permissions || []).filter(p => p !== "favicon");
  // Content scripts carry over unchanged, the passkey pair included: the
  // MAIN-world wrapper (webauthn-page.js) needs Firefox 128 (manifest.json's
  // gecko strict_min_version), and its ISOLATED bridge sends a per-document
  // key that background.js uses in place of Chromium's documentId.
  // The only web-accessible resource is panel.html, the frame content.js
  // draws its panels in (so no vault text is in the page's DOM). The page
  // never gets its URL: the frame sits in a closed shadow root. Firefox has
  // no use_dynamic_url (its moz-extension:// host is already a random
  // per-install UUID), so the key is dropped to keep the manifest clean.
  m.web_accessible_resources = (m.web_accessible_resources || []).map(entry => {
    const { use_dynamic_url, ...rest } = entry;
    return rest;
  });
  if (!m.web_accessible_resources.length) delete m.web_accessible_resources;
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
