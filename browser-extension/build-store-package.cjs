#!/usr/bin/env node
"use strict";
// Builds the upload zips for the browser extension stores.
//
//   localgatekeys-extension-<version>-chromium.zip  Chrome Web Store + Edge Add-ons
//   localgatekeys-extension-<version>-firefox.zip   addons.mozilla.org
//
// Only the runtime files in PACKAGE_FILES are copied (an allowlist, so new
// dev files never leak into a store upload). The Chromium manifest loses the
// dev "key" (each store assigns its own ID, see CHROME_WEB_STORE_EXTENSION_ID
// in src/localvault/config.py) and the Firefox-only browser_specific_settings.
// The Firefox manifest comes from build-firefox-manifest.cjs.
//
// Zips are deterministic: sorted entries, fixed timestamps, no extra fields,
// so the same source always yields byte-identical uploads.
//
// Usage: node browser-extension/build-store-package.cjs [outDir]
//        default outDir: build/store (gitignored via build/)
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");
const crypto = require("node:crypto");
const { firefoxManifest } = require("./build-firefox-manifest.cjs");

const SOURCE_DIR = __dirname;

// Everything the extension loads at runtime besides manifest.json. assets/
// (brand PNGs for docs) and the build scripts stay out of the store zip.
const PACKAGE_FILES = Object.freeze([
  "_locales/en/messages.json",
  "api.js",
  "background.js",
  "content.js",
  "heuristics.js",
  "icons/icon128.png",
  "icons/icon16.png",
  "icons/icon32.png",
  "icons/icon48.png",
  "login-safety.js",
  "popup.html",
  "popup.js",
  "site-logos.json",
  "webauthn-bridge.js",
  "webauthn-page.js",
]);

function chromiumStoreManifest(sourceManifest) {
  const m = JSON.parse(JSON.stringify(sourceManifest));
  // Each store assigns its own ID; the dev key must not ship in an upload.
  delete m.key;
  // Gecko settings are Firefox-only; Chrome warns about the unknown key.
  delete m.browser_specific_settings;
  return m;
}

// Files the manifest (and popup.html) make the browser load.
function referencedFiles(manifest) {
  const refs = new Set();
  for (const script of manifest.content_scripts || []) for (const file of script.js || []) refs.add(file);
  if (manifest.background?.service_worker) refs.add(manifest.background.service_worker);
  for (const file of manifest.background?.scripts || []) refs.add(file);
  if (manifest.action?.default_popup) refs.add(manifest.action.default_popup);
  for (const file of Object.values(manifest.action?.default_icon || {})) refs.add(file);
  for (const file of Object.values(manifest.icons || {})) refs.add(file);
  const popup = manifest.action?.default_popup;
  if (popup) {
    const html = fs.readFileSync(path.join(SOURCE_DIR, popup), "utf8");
    for (const match of html.matchAll(/\b(?:src|href)="([^":#?]+)"/g)) refs.add(match[1]);
  }
  // __MSG_*__ in the manifest and tr() in the scripts read the default locale.
  if (manifest.default_locale) refs.add(`_locales/${manifest.default_locale}/messages.json`);
  // background.js pulls in the namespace shim with importScripts on Chromium.
  refs.add("api.js");
  // background.js fetches the bundled site logos with runtime.getURL.
  refs.add("site-logos.json");
  return [...refs].sort();
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

// 2026-01-01 00:00:00 in MS-DOS date/time format.
const DOS_TIME = 0;
const DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1;

function zip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data } of [...entries].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    const nameBytes = Buffer.from(name, "utf8");
    const compressed = zlib.deflateRawSync(data, { level: 9 });
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed: 2.0 (deflate)
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(8, 8); // deflate
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // made by: 2.0, MS-DOS attributes
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    // extra/comment lengths, disk number, internal/external attributes: 0
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, compressed);
    centrals.push(central, nameBytes);
    offset += local.length + nameBytes.length + compressed.length;
  }
  const centralSize = centrals.reduce((sum, part) => sum + part.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, ...centrals, end]);
}

function packageEntries(manifest) {
  const missing = referencedFiles(manifest).filter(file => !PACKAGE_FILES.includes(file));
  if (missing.length) throw new Error(`Referenced but not in PACKAGE_FILES: ${missing.join(", ")}`);
  const entries = PACKAGE_FILES.map(name => ({ name, data: fs.readFileSync(path.join(SOURCE_DIR, ...name.split("/"))) }));
  entries.push({ name: "manifest.json", data: Buffer.from(JSON.stringify(manifest, null, 2) + "\n", "utf8") });
  return entries;
}

function build(outDir) {
  const source = JSON.parse(fs.readFileSync(path.join(SOURCE_DIR, "manifest.json"), "utf8"));
  fs.mkdirSync(outDir, { recursive: true });
  const outputs = {};
  for (const [variant, manifest] of [["chromium", chromiumStoreManifest(source)], ["firefox", firefoxManifest(source)]]) {
    const file = path.join(outDir, `localgatekeys-extension-${source.version}-${variant}.zip`);
    const bytes = zip(packageEntries(manifest));
    fs.writeFileSync(file, bytes);
    outputs[variant] = { file, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
  }
  return outputs;
}

module.exports = { PACKAGE_FILES, chromiumStoreManifest, referencedFiles, crc32, zip, build };

if (require.main === module) {
  const outDir = path.resolve(process.argv[2] || path.join(SOURCE_DIR, "..", "build", "store"));
  for (const [variant, { file, sha256 }] of Object.entries(build(outDir))) {
    console.log(`${variant.padEnd(8)} ${file}\n         sha256 ${sha256}`);
  }
}
