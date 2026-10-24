"use strict";
// Cross-browser namespace shim. Loaded before every other extension script:
// first entry of the content_scripts list, first script of popup.html, and
// imported by the service worker (Chrome) or listed first in
// background.scripts (Firefox, see build-firefox-manifest.cjs).
//
// Firefox exposes the promise-based `browser.*` namespace; Chromium exposes
// `chrome.*`, whose MV3 APIs also return promises when no callback is passed.
// Every call site therefore uses the promise form only.
//
// `var` (not `const`) so that re-injection of the same file into a frame by
// the popup's scripting.executeScript does not throw a redeclaration error.
//
// `browser` is picked only when it is the real extension namespace: in a
// content script on Chromium, a page element with id="browser" is reachable
// as globalThis.browser through named property access (DOM clobbering).
var api = typeof globalThis.browser?.runtime?.sendMessage === "function" ? globalThis.browser : globalThis.chrome;
