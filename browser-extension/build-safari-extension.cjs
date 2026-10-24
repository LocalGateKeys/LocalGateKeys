#!/usr/bin/env node
"use strict";
// Generates the web resources of the iPhone Safari Web Extension (target
// SafariSave in ios/project.yml) from this extension. The output is committed;
// tests/extension/safari-extension.test.cjs fails when it differs from a
// fresh build, so the shared scripts stay identical to the desktop ones.
//
// Shared, unchanged: api.js, heuristics.js, login-safety.js, content.js.
// Safari-only: background-safari.js (save prompts only; content.js turns
// filling off when it answers status with features.fill false) and a
// manifest derived from the Chromium one. The toolbar/extension icons are
// the desktop extension's PNGs, copied byte for byte (SAFARI_ICONS).
//
// Deterministic: fixed file list, LF line endings, stable JSON.
//
// Usage: node browser-extension/build-safari-extension.cjs [outDir]
//        default outDir: ios/SafariSave/Resources
const fs = require("node:fs");
const path = require("node:path");

const SOURCE_DIR = __dirname;
const DEFAULT_OUT_DIR = path.join(SOURCE_DIR, "..", "ios", "SafariSave", "Resources");
const SAFARI_FILES = Object.freeze(["api.js", "heuristics.js", "login-safety.js", "content.js", "background-safari.js"]);
// Binary, copied unchanged next to the scripts; named in the manifest's "icons".
const SAFARI_ICONS = Object.freeze({ 16: "icon16.png", 32: "icon32.png", 48: "icon48.png", 128: "icon128.png" });
const PASSKEY_SCRIPTS = new Set(["webauthn-page.js", "webauthn-bridge.js"]);
const DESCRIPTION = "Offers to save the logins you sign in with in Safari to LocalGateKeys on this iPhone.";

function safariManifest(source) {
  const m = JSON.parse(JSON.stringify(source));
  // Chromium/Firefox-only keys. No popup and no extension pages: the save
  // panel is drawn in the page. The icons point at the flat copies.
  for (const key of ["key", "minimum_chrome_version", "web_accessible_resources", "browser_specific_settings", "action", "icons"]) delete m[key];
  m.description = DESCRIPTION;
  m.icons = { ...SAFARI_ICONS };
  // webNavigation: background-safari.js checks the whole frame chain of an
  // iframe sender with getFrame (frameChainOk) instead of the top frame only.
  m.permissions = ["nativeMessaging", "storage", "webNavigation"];
  m.host_permissions = ["http://*/*", "https://*/*"];
  m.background = { scripts: ["api.js", "background-safari.js"], persistent: false };
  m.content_scripts = (m.content_scripts || [])
    .filter(cs => !(cs.js || []).some(f => PASSKEY_SCRIPTS.has(f)))
    .map(cs => {
      const out = { ...cs };
      if (out.world === "ISOLATED") delete out.world; // the default; older Safari ignores the key
      return out;
    });
  return m;
}

function build(outDir = DEFAULT_OUT_DIR) {
  const source = JSON.parse(fs.readFileSync(path.join(SOURCE_DIR, "manifest.json"), "utf8"));
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });
  for (const name of SAFARI_FILES) {
    const text = fs.readFileSync(path.join(SOURCE_DIR, name), "utf8").replace(/\r\n/g, "\n");
    fs.writeFileSync(path.join(outDir, name), text);
  }
  for (const name of Object.values(SAFARI_ICONS)) {
    fs.copyFileSync(path.join(SOURCE_DIR, "icons", name), path.join(outDir, name));
  }
  fs.writeFileSync(path.join(outDir, "manifest.json"), JSON.stringify(safariManifest(source), null, 2) + "\n");
  return outDir;
}

module.exports = { safariManifest, SAFARI_FILES, SAFARI_ICONS, build };

if (require.main === module) {
  const outDir = path.resolve(process.argv[2] || DEFAULT_OUT_DIR);
  console.log(`Safari resources written to ${build(outDir)}`);
}
