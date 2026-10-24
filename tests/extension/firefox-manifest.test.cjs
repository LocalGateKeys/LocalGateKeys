"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const EXT = path.join(__dirname, "..", "..", "browser-extension");
const { firefoxManifest, build } = require(path.join(EXT, "build-firefox-manifest.cjs"));
const chromeManifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8"));

test("Chromium manifest: shim first, all frames, CSP, gecko id, static host access with activeTab for manual fill", () => {
  const script = chromeManifest.content_scripts[0];
  assert.deepEqual(script.js, ["api.js", "heuristics.js", "login-safety.js", "content.js"]);
  assert.equal(script.all_frames, true);
  assert.equal(script.world, "ISOLATED");
  assert.deepEqual(script.matches, chromeManifest.host_permissions);
  assert.equal(chromeManifest.content_security_policy.extension_pages, "script-src 'self'; object-src 'self'");
  assert.equal(chromeManifest.browser_specific_settings.gecko.id, "localgatekeys@localgatekeys.app");
  assert.match(chromeManifest.browser_specific_settings.gecko.strict_min_version, /^\d+\.\d+$/);
  assert.ok(chromeManifest.permissions.includes("activeTab"));
  assert.equal(chromeManifest.background.service_worker, "background.js");
  assert.equal(chromeManifest.background.scripts, undefined, "Chrome 106+ must not see background.scripts");
  // No extension URL is reachable from web pages (in-page icons are inline SVG): nothing to probe.
  assert.equal(chromeManifest.web_accessible_resources, undefined);
  assert.equal(fs.existsSync(path.join(EXT, "auto-mode.js")), false, "orphaned auto-mode.js removed");
});

test("firefoxManifest() swaps the background model and drops Chromium-only keys", () => {
  const ff = firefoxManifest(chromeManifest);
  assert.deepEqual(ff.background, { scripts: ["api.js", "background.js"] });
  assert.equal(ff.key, undefined);
  assert.equal(ff.minimum_chrome_version, undefined);
  assert.equal(ff.permissions.includes("favicon"), false);
  assert.ok(ff.permissions.includes("nativeMessaging") && ff.permissions.includes("activeTab"));
  assert.deepEqual(ff.content_scripts, chromeManifest.content_scripts.filter(cs => !cs.js.some(f => f.startsWith("webauthn-"))));
  assert.deepEqual(ff.host_permissions, chromeManifest.host_permissions);
  assert.equal(ff.content_security_policy.extension_pages, chromeManifest.content_security_policy.extension_pages);
  assert.equal(ff.browser_specific_settings.gecko.id, "localgatekeys@localgatekeys.app");
  assert.equal(ff.web_accessible_resources, undefined, "no web-accessible resources in the Firefox build");
  assert.equal(firefoxManifest({ ...chromeManifest, web_accessible_resources: [{ resources: ["icons/icon32.png"], matches: ["https://*/*"] }] }).web_accessible_resources, undefined);
  assert.equal(chromeManifest.background.scripts, undefined, "input manifest is not mutated");
});

test("passkey scripts: MAIN wrapper and ISOLATED bridge at document_start on Chromium (111+), stripped from Firefox", () => {
  const passkey = chromeManifest.content_scripts.filter(cs => cs.js.some(f => f.startsWith("webauthn-")));
  assert.equal(passkey.length, 2);
  const [main, bridge] = passkey;
  assert.deepEqual(main.js, ["webauthn-page.js"]);
  assert.equal(main.world, "MAIN");
  assert.deepEqual(bridge.js, ["api.js", "webauthn-bridge.js"]);
  assert.equal(bridge.world, "ISOLATED");
  for (const cs of passkey) {
    assert.equal(cs.run_at, "document_start");
    assert.equal(cs.all_frames, true);
    assert.deepEqual(cs.matches, chromeManifest.host_permissions);
  }
  assert.equal(chromeManifest.minimum_chrome_version, "111", "manifest world: MAIN needs Chrome 111");
  const ff = firefoxManifest(chromeManifest);
  assert.ok(ff.content_scripts.every(cs => cs.js.every(f => !f.startsWith("webauthn-"))));
  assert.equal(ff.content_scripts.length, chromeManifest.content_scripts.length - 2);
});

test("build() copies the extension and writes the Firefox manifest", () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-ff-"));
  try {
    build(out);
    for (const name of ["api.js", "heuristics.js", "login-safety.js", "content.js", "background.js", "popup.html", "popup.js", "manifest.json"]) {
      assert.ok(fs.existsSync(path.join(out, name)), name);
    }
    assert.ok(fs.existsSync(path.join(out, "icons", "icon32.png")));
    assert.equal(fs.existsSync(path.join(out, "build-firefox-manifest.cjs")), false);
    const written = JSON.parse(fs.readFileSync(path.join(out, "manifest.json"), "utf8"));
    assert.deepEqual(written.background, { scripts: ["api.js", "background.js"] });
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test("background.js loads the shim in a worker and every script uses the api namespace", () => {
  const background = fs.readFileSync(path.join(EXT, "background.js"), "utf8");
  assert.match(background, /importScripts\("api\.js"\)/);
  for (const name of ["background.js", "content.js", "popup.js"]) {
    const text = fs.readFileSync(path.join(EXT, name), "utf8").split("\n").filter(l => !l.trim().startsWith("//")).join("\n");
    assert.equal(/\bchrome\.(runtime|tabs|storage|scripting|webNavigation)\b/.test(text), false, `${name} must call api.* not chrome.*`);
  }
  const popup = fs.readFileSync(path.join(EXT, "popup.html"), "utf8");
  assert.ok(popup.indexOf('src="api.js"') < popup.indexOf('src="popup.js"'));
  // `browser` only when it is the real namespace: a page element id="browser" must not win (DOM clobbering).
  assert.match(fs.readFileSync(path.join(EXT, "api.js"), "utf8"), /typeof globalThis\.browser\?\.runtime\?\.sendMessage === "function" \? globalThis\.browser : globalThis\.chrome/);
});
