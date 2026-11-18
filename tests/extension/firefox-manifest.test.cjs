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
  // The only extension URL web pages may load is the panel frame, behind a
  // per-session dynamic URL on Chromium (in-page icons are inline SVG).
  assert.deepEqual(chromeManifest.web_accessible_resources, [{ resources: ["panel.html"], matches: chromeManifest.host_permissions, use_dynamic_url: true }]);
  assert.equal(fs.existsSync(path.join(EXT, "auto-mode.js")), false, "orphaned auto-mode.js removed");
});

test("firefoxManifest() swaps the background model and drops Chromium-only keys", () => {
  const ff = firefoxManifest(chromeManifest);
  assert.deepEqual(ff.background, { scripts: ["api.js", "lookalike.js", "background.js"] });
  assert.equal(ff.key, undefined);
  assert.equal(ff.minimum_chrome_version, undefined);
  assert.equal(ff.permissions.includes("favicon"), false);
  assert.ok(ff.permissions.includes("nativeMessaging") && ff.permissions.includes("activeTab"));
  // Every content script carries over unchanged, the passkey pair included.
  assert.deepEqual(ff.content_scripts, chromeManifest.content_scripts);
  assert.deepEqual(ff.host_permissions, chromeManifest.host_permissions);
  assert.equal(ff.content_security_policy.extension_pages, chromeManifest.content_security_policy.extension_pages);
  assert.equal(ff.browser_specific_settings.gecko.id, "localgatekeys@localgatekeys.app");
  // Firefox keeps the panel frame but has no use_dynamic_url (its host is a
  // random per-install UUID); the key is dropped.
  assert.deepEqual(ff.web_accessible_resources, [{ resources: ["panel.html"], matches: chromeManifest.host_permissions }]);
  assert.equal(firefoxManifest({ ...chromeManifest, web_accessible_resources: undefined }).web_accessible_resources, undefined);
  assert.equal(chromeManifest.web_accessible_resources[0].use_dynamic_url, true, "input manifest is not mutated");
  assert.equal(chromeManifest.background.scripts, undefined, "input manifest is not mutated");
});

function assertPasskeyScripts(manifest, label) {
  const passkey = manifest.content_scripts.filter(cs => cs.js.some(f => f.startsWith("webauthn-")));
  assert.equal(passkey.length, 2, label);
  const [main, bridge] = passkey;
  assert.deepEqual(main.js, ["webauthn-page.js"], label);
  assert.equal(main.world, "MAIN", label);
  assert.deepEqual(bridge.js, ["api.js", "webauthn-bridge.js"], label);
  assert.equal(bridge.world, "ISOLATED", label);
  for (const cs of passkey) {
    assert.equal(cs.run_at, "document_start", label);
    assert.equal(cs.all_frames, true, label);
    assert.deepEqual(cs.matches, chromeManifest.host_permissions, label);
  }
}

test("passkey scripts: MAIN wrapper and ISOLATED bridge at document_start in every frame, on Chromium (111+) and Firefox (128+)", () => {
  assertPasskeyScripts(chromeManifest, "chromium");
  assert.equal(chromeManifest.minimum_chrome_version, "111", "manifest world: MAIN needs Chrome 111");
  const ff = firefoxManifest(chromeManifest);
  assertPasskeyScripts(ff, "firefox");
  assert.equal(ff.content_scripts.length, chromeManifest.content_scripts.length);
  // world: "MAIN" content scripts need Firefox 128.
  const [major] = ff.browser_specific_settings.gecko.strict_min_version.split(".").map(Number);
  assert.ok(major >= 128, "world: MAIN needs Firefox 128");
});

test("build() copies the extension and writes the Firefox manifest", () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "lgk-ff-"));
  try {
    build(out);
    for (const name of ["api.js", "heuristics.js", "login-safety.js", "content.js", "background.js", "lookalike.js", "psl-min.json", "THIRD-PARTY-NOTICES.txt", "popup.html", "popup.js", "manifest.json",
      "webauthn-page.js", "webauthn-bridge.js"]) {
      assert.ok(fs.existsSync(path.join(out, name)), name);
    }
    assert.ok(fs.existsSync(path.join(out, "icons", "icon32.png")));
    assert.equal(fs.existsSync(path.join(out, "build-firefox-manifest.cjs")), false);
    const written = JSON.parse(fs.readFileSync(path.join(out, "manifest.json"), "utf8"));
    assert.deepEqual(written.background, { scripts: ["api.js", "lookalike.js", "background.js"] });
    assertPasskeyScripts(written, "written firefox manifest");
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
