"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");

const EXT = path.join(__dirname, "..", "..", "browser-extension");
const store = require(path.join(EXT, "build-store-package.cjs"));
const sourceManifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8"));

// Minimal independent zip reader: walks the central directory and inflates
// each entry, checking sizes and CRCs against the headers.
function readZip(bytes) {
  const eocd = bytes.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.ok(eocd >= 0, "end of central directory");
  const count = bytes.readUInt16LE(eocd + 10);
  let at = bytes.readUInt32LE(eocd + 16);
  const entries = new Map();
  for (let i = 0; i < count; i++) {
    assert.equal(bytes.readUInt32LE(at), 0x02014b50, "central header");
    const method = bytes.readUInt16LE(at + 10);
    const crc = bytes.readUInt32LE(at + 16);
    const compressedSize = bytes.readUInt32LE(at + 20);
    const size = bytes.readUInt32LE(at + 24);
    const nameLength = bytes.readUInt16LE(at + 28);
    const extraLength = bytes.readUInt16LE(at + 30);
    const commentLength = bytes.readUInt16LE(at + 32);
    const localOffset = bytes.readUInt32LE(at + 42);
    const name = bytes.subarray(at + 46, at + 46 + nameLength).toString("utf8");
    assert.equal(bytes.readUInt32LE(localOffset), 0x04034b50, `local header ${name}`);
    const dataStart = localOffset + 30 + bytes.readUInt16LE(localOffset + 26) + bytes.readUInt16LE(localOffset + 28);
    const raw = bytes.subarray(dataStart, dataStart + compressedSize);
    const data = method === 8 ? zlib.inflateRawSync(raw) : Buffer.from(raw);
    assert.equal(data.length, size, `size ${name}`);
    assert.equal(store.crc32(data), crc, `crc ${name}`);
    assert.ok(!entries.has(name), `duplicate ${name}`);
    entries.set(name, data);
    at += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function buildOnce() {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-store-"));
  const outputs = store.build(outDir);
  return {
    outDir,
    chromium: fs.readFileSync(outputs.chromium.file),
    firefox: fs.readFileSync(outputs.firefox.file),
    outputs,
  };
}

const FORBIDDEN = [
  /(^|\/)\./, // dotfiles (.git, .DS_Store, .eslintrc ...)
  /(^|\/)(tests?|__tests__|node_modules|assets)\//,
  /\.(cjs|mjs|ts|map|md|ps1|py|sh|zip|log|pem|crx)$/i,
  /(^|\/)(package(-lock)?\.json|build-[^/]*)$/,
  /\.test\./,
];

test("store zips contain exactly the runtime allowlist plus manifest.json", () => {
  const { outDir, chromium, firefox, outputs } = buildOnce();
  try {
    assert.match(path.basename(outputs.chromium.file), new RegExp(`^localgatekeys-extension-${sourceManifest.version}-chromium\\.zip$`));
    for (const bytes of [chromium, firefox]) {
      const entries = readZip(bytes);
      assert.deepEqual([...entries.keys()].sort(), [...store.PACKAGE_FILES, "manifest.json"].sort());
      for (const name of entries.keys()) {
        for (const pattern of FORBIDDEN) assert.doesNotMatch(name, pattern, name);
        assert.ok(!name.includes("\\") && !name.startsWith("/") && !name.includes(".."), name);
      }
      for (const name of store.PACKAGE_FILES) {
        assert.ok(entries.get(name).equals(fs.readFileSync(path.join(EXT, name))), `${name} copied verbatim`);
      }
    }
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});

test("Chromium store manifest drops the dev key and gecko settings, keeps everything else", () => {
  const { outDir, chromium } = buildOnce();
  try {
    const manifest = JSON.parse(readZip(chromium).get("manifest.json").toString("utf8"));
    assert.equal(manifest.key, undefined, "dev key must not ship: the store assigns the ID");
    assert.equal(manifest.browser_specific_settings, undefined);
    assert.equal(manifest.update_url, undefined);
    const expected = { ...sourceManifest };
    delete expected.key;
    delete expected.browser_specific_settings;
    assert.deepEqual(manifest, expected);
    // The source manifest keeps its key for unpacked developer installs.
    assert.ok(sourceManifest.key);
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});

test("Firefox store manifest is the build-firefox-manifest variant", () => {
  const { firefoxManifest } = require(path.join(EXT, "build-firefox-manifest.cjs"));
  const { outDir, firefox } = buildOnce();
  try {
    const manifest = JSON.parse(readZip(firefox).get("manifest.json").toString("utf8"));
    assert.deepEqual(manifest, firefoxManifest(sourceManifest));
    assert.equal(manifest.key, undefined);
    assert.equal(manifest.browser_specific_settings.gecko.id, "localgatekeys@localgatekeys.app");
    assert.deepEqual(manifest.background, { scripts: ["api.js", "background.js"] });
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});

test("every file the manifests and popup load is packaged", () => {
  for (const manifest of [store.chromiumStoreManifest(sourceManifest), require(path.join(EXT, "build-firefox-manifest.cjs")).firefoxManifest(sourceManifest)]) {
    for (const file of store.referencedFiles(manifest)) assert.ok(store.PACKAGE_FILES.includes(file), file);
  }
  // Nothing in the allowlist is dead weight either.
  const referenced = new Set(store.referencedFiles(sourceManifest));
  for (const file of store.PACKAGE_FILES) assert.ok(referenced.has(file), `${file} is not loaded by anything`);
});

test("store zips are byte-for-byte reproducible", () => {
  const first = buildOnce();
  const second = buildOnce();
  try {
    assert.ok(first.chromium.equals(second.chromium));
    assert.ok(first.firefox.equals(second.firefox));
    assert.equal(first.outputs.chromium.sha256, second.outputs.chromium.sha256);
  } finally {
    fs.rmSync(first.outDir, { recursive: true, force: true });
    fs.rmSync(second.outDir, { recursive: true, force: true });
  }
});
