#!/usr/bin/env node
"use strict";
// Generates the web resources of the iPhone Safari Web Extension (target
// SafariSave in ios/project.yml) from this extension. The output is committed;
// tests/extension/safari-extension.test.cjs fails when it differs from a
// fresh build, so the shared scripts stay identical to the desktop ones.
//
// Shared, unchanged: api.js, heuristics.js, login-safety.js, content.js,
// lookalike.js, plus psl-min.json and its MPL notice (SAFARI_DATA).
// Safari-only: background-safari.js (save prompts only; content.js turns
// filling off when it answers status with features.fill false), the toolbar
// popup popup-safari.html/.js (SAFARI_POPUP: the pending-save count, the
// per-site save switch, Open LocalGateKeys on the Mac; it never lists or fills
// logins), the save panel frame panel.html/panel.js (SAFARI_PANEL, see
// safariPanelHtml) and a manifest derived from the Chromium one. The toolbar/extension icons are
// the desktop extension's PNGs, copied byte for byte (SAFARI_ICONS).
//
// Deterministic: fixed file list, LF line endings, stable JSON.
//
// Usage: node browser-extension/build-safari-extension.cjs [outDir [ios|macos]]
//        no arguments: both outputs, ios/SafariSave/Resources (iPhone) and
//        ios/SafariMac/Resources (Mac). Same script set; only the manifest
//        description names the device.
const fs = require("node:fs");
const path = require("node:path");

const SOURCE_DIR = __dirname;
const DEFAULT_OUT_DIR = path.join(SOURCE_DIR, "..", "ios", "SafariSave", "Resources");
const MAC_OUT_DIR = path.join(SOURCE_DIR, "..", "ios", "SafariMac", "Resources");
const SAFARI_FILES = Object.freeze(["api.js", "heuristics.js", "login-safety.js", "content.js", "lookalike.js", "background-safari.js"]);
// Data next to the scripts: the suffix list background-safari.js reads for
// lookalike.js, and its MPL notice. Copied unchanged (LF).
const SAFARI_DATA = Object.freeze(["psl-min.json", "THIRD-PARTY-NOTICES.txt"]);
// The toolbar button's popup (manifest "action"), Safari's own: the desktop
// popup.html talks to the Windows broker and is not shipped.
const SAFARI_POPUP = Object.freeze(["popup-safari.html", "popup-safari.js"]);
// The panel frame content.js draws its save prompts in (web-accessible, see
// safariManifest): the desktop panel.js unchanged, panel.html adapted by
// safariPanelHtml for the flat resource folder.
const SAFARI_PANEL = Object.freeze(["panel.html", "panel.js"]);
// Toolbar icon sizes Safari picks from (the desktop extension's PNGs).
const SAFARI_ACTION_ICONS = Object.freeze({ 16: "icon16.png", 32: "icon32.png", 48: "icon48.png" });
// Binary, copied unchanged next to the scripts; named in the manifest's "icons".
const SAFARI_ICONS = Object.freeze({ 16: "icon16.png", 32: "icon32.png", 48: "icon48.png", 128: "icon128.png" });
const PASSKEY_SCRIPTS = new Set(["webauthn-page.js", "webauthn-bridge.js"]);
const DESCRIPTIONS = Object.freeze({
  ios: "Offers to save the logins you sign in with in Safari to LocalGateKeys on this device.",
  macos: "Offers to save the logins you sign in with in Safari to LocalGateKeys on this Mac.",
});

function safariManifest(source, platform = "ios") {
  if (!Object.hasOwn(DESCRIPTIONS, platform)) throw new Error(`unknown platform ${platform}`);
  const m = JSON.parse(JSON.stringify(source));
  // Chromium/Firefox-only keys, and the desktop popup (replaced below by the
  // Safari one). The icons point at the flat copies.
  for (const key of ["key", "minimum_chrome_version", "web_accessible_resources", "browser_specific_settings", "action", "icons", "commands"]) delete m[key];
  // The save panel is drawn in panel.html, framed into the page by content.js
  // (its frameCapable() looks for this entry), as on Chrome, Edge and Firefox.
  // Safari has no use_dynamic_url (its extension host is a random id Safari
  // assigns). Where the frame never reports in (a page whose CSP blocks it),
  // content.js falls back to its in-page panel on Safari only.
  m.web_accessible_resources = [{ resources: ["panel.html"], matches: ["http://*/*", "https://*/*"] }];
  m.description = `__MSG_ext_description_${platform}__`;
  m.icons = { ...SAFARI_ICONS };
  // The toolbar button: without it Safari shows no icon and users think the
  // extension is missing. Its badge is the pending-save count.
  m.action = { default_title: "__MSG_ext_name__", default_popup: "popup-safari.html", default_icon: { ...SAFARI_ACTION_ICONS } };
  // webNavigation: background-safari.js checks the whole frame chain of an
  // iframe sender with getFrame (frameChainOk) instead of the top frame only.
  m.permissions = ["nativeMessaging", "storage", "webNavigation"];
  m.host_permissions = ["http://*/*", "https://*/*"];
  m.background = { scripts: ["api.js", "lookalike.js", "background-safari.js"], persistent: false };
  m.content_scripts = (m.content_scripts || [])
    .filter(cs => !(cs.js || []).some(f => PASSKEY_SCRIPTS.has(f)))
    .map(cs => {
      const out = { ...cs };
      if (out.world === "ISOLATED") delete out.world; // the default; older Safari ignores the key
      return out;
    });
  return m;
}

// panel.html for Safari: the brand mark is the flat icon48.png (the resource
// folder has no icons/ directory), and no generator.js (Safari offers no
// password generator; panel.js draws none without it). Throws if the desktop
// file no longer has what is replaced, so the build cannot drift silently.
function safariPanelHtml(text) {
  const swaps = [['url("icons/icon48.png")', 'url("icon48.png")'], ['<script src="generator.js"></script>\n', ""]];
  for (const [from, to] of swaps) {
    if (text.split(from).length !== 2) throw new Error(`panel.html: expected one ${JSON.stringify(from)}`);
    text = text.replace(from, to);
  }
  return text;
}

function build(outDir = DEFAULT_OUT_DIR, platform = "ios") {
  const source = JSON.parse(fs.readFileSync(path.join(SOURCE_DIR, "manifest.json"), "utf8"));
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });
  for (const name of [...SAFARI_FILES, ...SAFARI_DATA, ...SAFARI_POPUP]) {
    const text = fs.readFileSync(path.join(SOURCE_DIR, name), "utf8").replace(/\r\n/g, "\n");
    fs.writeFileSync(path.join(outDir, name), text);
  }
  for (const name of SAFARI_PANEL) {
    const text = fs.readFileSync(path.join(SOURCE_DIR, name), "utf8").replace(/\r\n/g, "\n");
    fs.writeFileSync(path.join(outDir, name), name === "panel.html" ? safariPanelHtml(text) : text);
  }
  // Locale catalogs for the __MSG_*__ name in the manifest and tr() in the scripts.
  fs.cpSync(path.join(SOURCE_DIR, "_locales"), path.join(outDir, "_locales"), { recursive: true });
  for (const name of Object.values(SAFARI_ICONS)) {
    fs.copyFileSync(path.join(SOURCE_DIR, "icons", name), path.join(outDir, name));
  }
  fs.writeFileSync(path.join(outDir, "manifest.json"), JSON.stringify(safariManifest(source, platform), null, 2) + "\n");
  return outDir;
}

module.exports = { safariManifest, safariPanelHtml, SAFARI_FILES, SAFARI_DATA, SAFARI_POPUP, SAFARI_PANEL, SAFARI_ICONS, SAFARI_ACTION_ICONS, DESCRIPTIONS, DEFAULT_OUT_DIR, MAC_OUT_DIR, build };

if (require.main === module) {
  if (process.argv[2]) {
    console.log(`Safari resources written to ${build(path.resolve(process.argv[2]), process.argv[3] || "ios")}`);
  } else {
    console.log(`Safari resources written to ${build(DEFAULT_OUT_DIR, "ios")}`);
    console.log(`Safari resources written to ${build(MAC_OUT_DIR, "macos")}`);
  }
}
