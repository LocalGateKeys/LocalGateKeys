/* jsdom harness for the content scripts. No network, no real extension APIs.
 *
 * jsdom has no layout engine, so three things are stubbed deterministically:
 *   - getBoundingClientRect: explicit rects via setRect(), otherwise form
 *     controls and anchors are stacked vertically in composed-tree order,
 *     position:fixed boxes with inline pixel geometry (the extension's icon
 *     and panel hosts) are laid out from that style (height "auto" counts as
 *     AUTO_HEIGHT), and containers get the viewport rect.
 *   - getComputedStyle: jsdom reports opacity "" (which login-safety would read
 *     as 0); defaults are normalised to visible.
 *   - elementFromPoint (document and ShadowRoot): topmost = last element in
 *     composed order (layout controls, setRect() elements and fixed boxes)
 *     whose rect contains the point; retargeted to the caller's
 *     tree the way browsers do, so shadow hosts hide their children from the
 *     document-level call.
 * Trusted events come from jsdom's internal fireAnEvent (isTrusted === true),
 * which is what content.js requires before acting on page events.
 *
 * The panel frame: content.js draws its panels in panel.html, framed into the
 * page. jsdom does not load frames inside shadow roots, so the harness gives
 * each panel iframe its own jsdom document built from panel.html, runs api.js,
 * generator.js and panel.js there (window.name = the iframe's name, window.top
 * = the page), and routes the frame's ui_* messages to the content script as
 * the service worker does ({command:"ui", op, frame:{id, document}}).
 * p.panelRoot() is the current frame's document (or, without the frame, the
 * closed shadow root of the in-page fallback). frame:false gives a manifest
 * without web-accessible resources (the Safari build): no frame.
 * The frame's performance.now() advances 1000 ms per call, so the panel's arm
 * delay never blocks a test click unless a test pins the clock (p.frameClock).
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { JSDOM, VirtualConsole } = require("jsdom");
const { fireAnEvent } = require("jsdom/lib/jsdom/living/helpers/events");
const { implForWrapper } = require("jsdom/lib/jsdom/living/generated/utils");
const EventImpl = require("jsdom/lib/jsdom/living/generated/Event");
const KeyboardEventImpl = require("jsdom/lib/jsdom/living/generated/KeyboardEvent");
const MouseEventImpl = require("jsdom/lib/jsdom/living/generated/MouseEvent");
const SubmitEventImpl = require("jsdom/lib/jsdom/living/generated/SubmitEvent");

const { after } = require("node:test");
const i18nStub = require("./i18n-stub.cjs");

const EXT = path.join(__dirname, "..", "..", "browser-extension");
// content.js arms intervals (status polling, banner expiry). Closing every
// window when the file's root suite ends lets the node --test subprocess exit.
const openPages = [];
after(() => { for (const page of openPages) { try { page.window.close(); } catch { /* already closed */ } } });
const read = name => fs.readFileSync(path.join(EXT, name), "utf8");
const SOURCES = { "api.js": read("api.js"), "heuristics.js": read("heuristics.js"), "login-safety.js": read("login-safety.js"), "content.js": read("content.js") };
const PANEL = { html: read("panel.html"), generator: read("generator.js"), panel: read("panel.js") };
const MANIFEST = JSON.parse(read("manifest.json"));

const LAYOUT_SELECTOR = 'input,button,textarea,select,a,[role="button"],[role="menuitem"],[role="alert"]';
const AUTO_HEIGHT = 120;
const px = value => { const m = /^(-?\d+(?:\.\d+)?)px$/.exec(value || ""); return m ? Number(m[1]) : null; };

function composedElements(root, out = []) {
  for (const el of root.querySelectorAll("*")) {
    out.push(el);
    if (el.shadowRoot) composedElements(el.shadowRoot, out);
  }
  return out;
}

function createPage({
  html = "",
  url = "https://example.test/login",
  scripts = ["api.js", "heuristics.js", "login-safety.js", "content.js"],
  respond = null,
  blockedOrigins = [],
  runtimeId = "testextension",
  startClock = 1_700_000_000_000,
  frame = true,
  frameSetup = null, // (frameWindow) => void: extra globals for panel.js, set before it runs
  manifest = null, // (MANIFEST) => manifest: what runtime.getManifest() reports (e.g. Firefox's form)
  selfOrigin = null, // self.origin when it differs from the URL's ("null": a sandboxed, opaque-origin document)
} = {}) {
  const virtualConsole = new VirtualConsole(); // swallow "not implemented: form submission"
  const dom = new JSDOM(`<!doctype html><html><head></head><body>${html}</body></html>`, { url, runScripts: "outside-only", pretendToBeVisual: true, virtualConsole });
  const w = dom.window;
  const d = w.document;
  if (selfOrigin !== null) Object.defineProperty(w, "origin", { value: selfOrigin, configurable: true });

  // ---- clock (content.js reads Date.now() through the page realm's Date)
  const clock = { now: startClock };
  w.Date.now = () => clock.now;

  // ---- layout stubs
  const rects = new WeakMap();
  const setRect = (el, r) => rects.set(el, { left: 20, top: 20, width: 200, height: 32, ...r });
  const isHidden = el => {
    for (let p = el; p && p.nodeType === 1; p = p.parentElement || p.getRootNode()?.host || null) {
      const s = p.style;
      if (s && (s.display === "none" || s.visibility === "hidden" || s.opacity === "0")) return true;
      if (p.hidden) return true;
    }
    return false;
  };
  const fixedRect = el => {
    const s = el.style;
    if (!s || s.position !== "fixed") return null;
    const width = px(s.width);
    if (width === null) return null;
    const height = px(s.height) ?? AUTO_HEIGHT;
    let left = px(s.left), top = px(s.top);
    if (left === null) { const right = px(s.right); if (right === null) return null; left = w.innerWidth - right - width; }
    if (top === null) { const bottom = px(s.bottom); if (bottom === null) return null; top = w.innerHeight - bottom - height; }
    return { left, top, width, height };
  };
  const rectOf = el => {
    const explicit = rects.get(el);
    if (explicit) return explicit;
    const fixed = fixedRect(el);
    if (fixed) return fixed;
    if (el.matches && el.matches(LAYOUT_SELECTOR)) {
      const index = composedElements(d).filter(x => x.matches(LAYOUT_SELECTOR)).indexOf(el);
      return { left: 20, top: 20 + index * 50, width: 200, height: 32 };
    }
    return { left: 0, top: 0, width: 1024, height: 768 };
  };
  const box = r => ({ ...r, right: r.left + r.width, bottom: r.top + r.height, x: r.left, y: r.top });
  w.Element.prototype.getBoundingClientRect = function () { return box(rectOf(this)); };

  const realGCS = w.getComputedStyle.bind(w);
  w.getComputedStyle = el => {
    const s = realGCS(el);
    return new Proxy(s, {
      get(t, k) {
        if (k === "opacity") return t.opacity === "" ? "1" : t.opacity;
        if (k === "visibility") return t.visibility || "visible";
        if (k === "display") return t.display || "block";
        const v = t[k];
        return typeof v === "function" ? v.bind(t) : v;
      },
    });
  };

  const topmostAt = (x, y) => {
    const hits = composedElements(d).filter(el => {
      if (!(rects.has(el) || el.matches(LAYOUT_SELECTOR) || fixedRect(el)) || isHidden(el)) return false;
      const r = box(rectOf(el));
      return x >= r.left && x < r.right && y >= r.top && y < r.bottom;
    });
    return hits[hits.length - 1] || d.body;
  };
  d.elementFromPoint = (x, y) => {
    let el = topmostAt(x, y);
    while (el && el.getRootNode() !== d) el = el.getRootNode().host;
    return el;
  };
  w.ShadowRoot.prototype.elementFromPoint = function (x, y) {
    let el = topmostAt(x, y);
    while (el && el.getRootNode() !== this) {
      const root = el.getRootNode();
      if (!(root instanceof w.ShadowRoot)) return null;
      el = root.host;
    }
    return el;
  };

  // ---- record closed shadow roots created by the content script (panel, icons)
  const shadows = new WeakMap();
  const attach = w.Element.prototype.attachShadow;
  w.Element.prototype.attachShadow = function (init) { const root = attach.call(this, init); shadows.set(this, root); return root; };

  // ---- extension API mock (promise form only)
  const messages = [];
  const commandListeners = [], storageListeners = [];
  const storage = { automatic_save_blocked_origins: [...blockedOrigins] };
  const chrome = {
    i18n: { getMessage: i18nStub.getMessage },
    runtime: {
      id: runtimeId,
      getURL: p => `chrome-extension://${runtimeId}/${p}`,
      sendMessage: async request => {
        messages.push(request);
        const reply = respond ? await respond(request, messages) : null;
        return reply ?? { ok: false, error: "unsupported_request" };
      },
      onMessage: { addListener: f => commandListeners.push(f) },
    },
    storage: {
      local: { get: async defaults => ({ ...defaults, ...storage }), set: async value => { Object.assign(storage, value); } },
      onChanged: { addListener: f => storageListeners.push(f) },
    },
  };
  w.chrome = chrome;
  chrome.runtime.getManifest = () => (!frame ? { ...MANIFEST, web_accessible_resources: undefined } : manifest ? manifest(MANIFEST) : MANIFEST);

  // ---- the panel frame (see the header)
  const frames = new WeakMap(); // iframe -> { dom, window, sent }
  const frameLog = [];
  const frameClock = { pinned: null, now: 0 };
  let nextFrameId = 7;
  const deliver = message => new Promise(resolve => {
    if (!commandListeners.length) { resolve(undefined); return; }
    const kept = commandListeners[0](message, { id: runtimeId }, resolve);
    if (kept !== true) setImmediate(() => resolve(undefined));
  });
  const startFrame = iframe => {
    const frameId = nextFrameId++;
    const fdom = new JSDOM(PANEL.html.replace(/<script\b[^>]*><\/script>/g, ""), { url: `chrome-extension://${runtimeId}/panel.html`, runScripts: "outside-only", pretendToBeVisual: true, virtualConsole });
    const fw = fdom.window;
    fw.name = iframe.name;
    fw.performance.now = () => (frameClock.pinned ?? (frameClock.now += 1000));
    const sentByFrame = [];
    fw.chrome = {
      i18n: { getMessage: i18nStub.getMessage },
      runtime: {
        id: runtimeId,
        getURL: p => `chrome-extension://${runtimeId}/${p}`,
        // The service worker's relay: ui_pull/ui_size/ui_event to the content
        // script, with the frame's id and document added.
        sendMessage: async request => {
          sentByFrame.push(request);
          const op = { ui_pull: "pull", ui_size: "size", ui_event: "event" }[request.type];
          if (!op) return { ok: false, error: "unsupported_request" };
          const { type, ...fields } = request;
          return (await deliver({ ...fields, command: "ui", op, frame: { id: frameId, document: `doc-${frameId}` } })) ?? { ok: false };
        },
        onMessage: { addListener: () => { throw new Error("panel.js must not listen for messages"); } },
      },
      storage: chrome.storage,
    };
    const fctx = fdom.getInternalVMContext();
    vm.runInContext(SOURCES["api.js"], fctx, { filename: "api.js" });
    vm.runInContext(PANEL.generator, fctx, { filename: "generator.js" });
    if (frameSetup) frameSetup(fw);
    // window.top cannot be redefined on a jsdom window: panel.js sees a
    // window whose top is the page, everything else is the frame's own.
    fw.__lgkFrameWindow = new Proxy(fw, { get: (t, k) => (k === "top" ? w : Reflect.get(t, k)), set: (t, k, v) => Reflect.set(t, k, v) });
    vm.runInContext(`(function (window) {${PANEL.panel}\n}).call(globalThis, globalThis.__lgkFrameWindow);`, fctx, { filename: "panel.js" });
    const record = { dom: fdom, window: fw, sent: sentByFrame, id: frameId, iframe };
    frames.set(iframe, record);
    frameLog.push(record);
    openPages.push({ window: fw });
  };
  const srcDescriptor = Object.getOwnPropertyDescriptor(w.HTMLIFrameElement.prototype, "src");
  Object.defineProperty(w.HTMLIFrameElement.prototype, "src", {
    ...srcDescriptor,
    set(value) {
      srcDescriptor.set.call(this, value);
      if (String(value) === `chrome-extension://${runtimeId}/panel.html`) queueMicrotask(() => startFrame(this));
    },
  });

  const context = dom.getInternalVMContext();
  const load = () => { for (const name of scripts) vm.runInContext(SOURCES[name], context, { filename: name }); };

  const tick = async (n = 3) => { for (let i = 0; i < n; i++) await new Promise(r => setImmediate(r)); };
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const trusted = (target, type, attributes = {}, Impl = EventImpl) => {
    const attrs = { bubbles: true, cancelable: true, ...attributes };
    if (attrs.submitter) attrs.submitter = implForWrapper(attrs.submitter);
    return fireAnEvent(type, implForWrapper(target), Impl, attrs);
  };
  const command = (cmd, extra = {}) => new Promise(resolve => {
    if (!commandListeners.length) throw new Error("content script registered no command listener");
    commandListeners[0]({ ...extra, command: cmd }, { id: runtimeId }, resolve);
  });
  const sent = type => messages.filter(m => m.type === type);
  // The panel host carries a random per-page attribute: find it as the div
  // with a closed shadow root that content.js appends to <html>.
  const panelHost = () => Array.from(d.documentElement.children).find(e => e.tagName === "DIV" && shadows.get(e)?.mode === "closed") || null;
  const panelVisible = () => { const host = panelHost(); return !!host && host.style.display === "block"; };
  // The shown panel frame (not one still loading behind it), if any.
  const panelFrame = () => {
    const host = panelHost();
    const iframes = host ? Array.from(shadows.get(host)?.querySelectorAll("iframe") || []).filter(f => !f.classList.contains("pending")) : [];
    return iframes.length ? frames.get(iframes[iframes.length - 1]) || null : null;
  };
  const panelRoot = () => {
    const host = panelHost();
    if (!host) return null;
    const shown = panelFrame();
    return shown ? shown.window.document : shadows.get(host) || null;
  };
  const panelText = () => {
    const shown = panelFrame();
    if (shown) return shown.window.document.getElementById("root")?.textContent || "";
    const host = panelHost();
    return host ? (shadows.get(host)?.textContent || "") : "";
  };
  const fieldIcons = () => Array.from(d.querySelectorAll("[data-localvault-field-icon]"));
  const otpIcons = () => Array.from(d.querySelectorAll("[data-localgatekeys-otp-icon]"));
  const cardIcons = () => Array.from(d.querySelectorAll("[data-localgatekeys-card-icon]"));
  const identityIcons = () => Array.from(d.querySelectorAll("[data-localgatekeys-identity-icon]"));
  const openShadow = (host, innerHtml) => { const root = attach.call(host, { mode: "open" }); root.innerHTML = innerHtml; return root; };

  const page = {
    dom, window: w, document: d, chrome, clock, messages, storage, commandListeners,
    load, tick, sleep, trusted, command, sent, storageListeners, setRect, panelHost, panelVisible, panelText, panelRoot, panelFrame, frameLog, frameClock, fieldIcons, otpIcons, cardIcons, identityIcons, openShadow, shadows,
    S: () => w.LGKLoginSafety, H: () => w.LGKHeuristics,
    impls: { EventImpl, KeyboardEventImpl, MouseEventImpl, SubmitEventImpl },
  };
  openPages.push(page);
  return page;
}

module.exports = { createPage, SOURCES, EXT };
