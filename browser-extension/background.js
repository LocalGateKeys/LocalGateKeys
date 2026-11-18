"use strict";
// Chrome runs this file as a classic service worker: pull in the namespace
// shim. Firefox (build-firefox-manifest.cjs) lists api.js before this file in
// background.scripts, so `api` already exists there and importScripts is absent.
if (typeof api === "undefined" && typeof importScripts === "function") importScripts("api.js");
// The lookalike classifier (same algorithm as the app's) for the check that
// needs no saved origins: Firefox lists it in background.scripts instead.
if (typeof LGKLookalike === "undefined" && typeof importScripts === "function") importScripts("lookalike.js");
const HOST_NAME = "com.localgatekeys.app";
const PROTOCOL = 2;
const IDENTITY_FILL_PROTOCOL = 1;
const CARD_FILL_PROTOCOL = 1;
const PASSKEY_PROTOCOL = 1;
const PASSKEY_TYPES = new Set(["passkey_create_browser","passkey_get_browser"]);
// Two-step save: the page reports whether it handed a created passkey to the
// site (confirm) or could not (discard). Only the operation id comes from the
// page; the context is built from the sender like the create's, so the app
// matches it to that create alone.
const PASSKEY_OUTCOME_TYPES = new Set(["passkey_confirm_browser","passkey_discard_browser"]);
// Serialized WebAuthn options from webauthn-page.js; larger requests go to the browser.
const MAX_PASSKEY_OPTIONS = 65536;
const CARD_FIELDS = new Set(["cc-name","cc-number","cc-exp","cc-exp-month","cc-exp-year","cc-csc","cc-type"]);
// Actions that may carry the page URL for multi-URL (starts_with) matching.
const URL_ACTIONS = new Set(["begin_browser","get_browser","fill_grant_browser"]);
const EXTENSION_VERSION = api.runtime.getManifest().version;
const MAX_FRAME_DEPTH = 32;
// content.js and webauthn-bridge.js each draw their own: 32 random hex digits, once per document.
const DOCUMENT_KEY = /^[0-9a-f]{32}$/;

function canonicalOrigin(value) {
  const u = new URL(value);
  if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) throw new Error("Expected an origin");
  const local = u.hostname === "localhost" || u.hostname.endsWith(".localhost") || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new Error("Use HTTPS (or local test pages)");
  return u.origin;
}
// The document's real origin where the browser reports it (Chromium,
// Firefox 126+): an opaque-origin document (sandboxed iframe, CSP sandbox)
// has the site's URL but origin "null" and must never be treated as the site.
// Browsers without sender.origin fall back to the URL (content scripts check
// self.origin themselves).
function senderOriginOk(sender, origin) {
  if (!("origin" in sender) || sender.origin === undefined) return true;
  if (typeof sender.origin !== "string" || sender.origin === "null") return false;
  try { return canonicalOrigin(sender.origin) === origin; } catch { return false; }
}
// The page URL a content script reports next to its origin. It is forwarded
// only when it is a plain string whose canonical origin equals the
// browser-derived sender origin, carries no credentials and no fragment;
// anything else is dropped (the broker then matches the origin alone).
function pageUrlFor(value, origin) {
  if (typeof value !== "string" || !value || value.length > 4096 || value.includes("\0")) return undefined;
  let u;
  try { u = new URL(value); } catch { return undefined; }
  if (u.username || u.password) return undefined;
  try { if (canonicalOrigin(u.origin) !== origin) return undefined; } catch { return undefined; }
  u.hash = "";
  return u.href;
}
const readableErrors = {
  get agent_offline() { return tr("bg_err_agent_offline"); },
  get agent_state_missing() { return tr("bg_err_agent_state_missing"); },
  get agent_state_invalid() { return tr("bg_err_agent_state_invalid"); },
  get agent_access_denied() { return tr("bg_err_agent_access_denied"); },
  get agent_unavailable() { return tr("bg_err_agent_unavailable"); },
  get agent_busy() { return tr("bg_err_agent_busy"); },
  get agent_connection_lost() { return tr("bg_err_agent_connection_lost"); },
  get agent_connection_changed() { return tr("bg_err_agent_connection_changed"); },
  get bridge_dependencies_missing() { return tr("bg_err_bridge_dependencies_missing"); },
  get bridge_protocol_error() { return tr("bg_err_bridge_protocol_error"); },
  get bridge_internal_error() { return tr("bg_err_bridge_internal_error"); },
  get caller_not_browser() { return tr("bg_err_caller_not_browser"); },
  get rate_limited() { return tr("bg_err_rate_limited"); },
  get unauthorized() { return tr("bg_err_unauthorized"); },
  get version_mismatch() { return tr("bg_err_version_mismatch"); },
  get client_not_allowed() { return tr("bg_err_client_not_allowed"); },
  get session_changed() { return tr("bg_err_session_changed"); },
  get integration_disabled() { return tr("bg_err_integration_disabled"); },
  get not_found() { return tr("bg_err_not_found"); },
  get destination_changed() { return tr("bg_err_destination_changed"); },
  get busy() { return tr("bg_err_busy"); },
  get identity_not_found() { return tr("bg_err_identity_not_found"); },
  get invalid_identity_fields() { return tr("bg_err_invalid_identity_fields"); },
  get user_cancelled() { return tr("bg_err_user_cancelled"); },
  get user_gesture_required() { return tr("bg_err_user_gesture_required"); },
  get gesture_nonce_invalid() { return tr("bg_err_gesture_nonce_invalid"); },
  get gesture_nonce_required() { return tr("bg_err_gesture_nonce_required"); },
  get origin_mismatch() { return tr("bg_err_origin_mismatch"); },
  get invalid_request() { return tr("bg_err_invalid_request"); },
  get invalid_approval() { return tr("bg_err_invalid_approval"); },
  get card_not_found() { return tr("bg_err_card_not_found"); },
  get invalid_card_fields() { return tr("bg_err_invalid_card_fields"); },
  get totp_not_found() { return tr("bg_err_totp_not_found"); },
  get unsupported_request() { return tr("bg_err_unsupported_request"); },
};
function itemLimitMessage(limit) {
  const count = Number.isInteger(limit) && limit > 0 ? limit : 7;
  return tr("content_item_limit", count);
}
function hostError(message) {
  if (/not found/i.test(message)) return tr("bg_host_not_registered");
  if (/forbidden/i.test(message)) return tr("bg_host_forbidden");
  if (/exited/i.test(message)) return tr("bg_host_exited");
  return tr("bg_host_failed");
}
const TIMEOUT_CANCEL = {begin_browser:"cancel_browser",get_browser:"cancel_browser",
  begin_identity_browser:"cancel_identity_browser",approve_identity_browser:"cancel_identity_browser",release_identity_browser:"cancel_identity_browser",
  begin_card_browser:"cancel_card_browser",approve_card_browser:"cancel_card_browser",release_card_browser:"cancel_card_browser",
  passkey_create_browser:"passkey_discard_browser"};
// Identifier-first logins: step one's username per tab, same origin, 5 min,
// handed out once. Kept in worker memory and mirrored to storage.session
// (browser memory, never on disk, not readable by content scripts), so an idle
// worker that the browser stops between the two pages does not lose it.
const STEP_USERNAME_MS = 300000;
const stepUsernames = new Map();
const stepKey = tabId => `step_username:${tabId}`;
function sessionArea() { try { return api.storage?.session || null; } catch { return null; } }
async function keepStepUsername(tabId, value) {
  stepUsernames.set(tabId, value);
  try { await sessionArea()?.set({[stepKey(tabId)]:value}); } catch { /* memory copy only */ }
}
async function takeStepUsername(tabId) {
  let kept = stepUsernames.get(tabId) || null;
  stepUsernames.delete(tabId);
  const area = sessionArea();
  if (area) {
    try {
      if (!kept) kept = (await area.get(stepKey(tabId)))?.[stepKey(tabId)] || null;
      await area.remove(stepKey(tabId));
    } catch { /* memory copy only */ }
  }
  return kept && typeof kept === "object" ? kept : null;
}
function dropStepUsername(tabId) {
  stepUsernames.delete(tabId);
  try { Promise.resolve(sessionArea()?.remove(stepKey(tabId))).catch(() => {}); } catch { /* none */ }
}
// Finding W-L2: site_logins_browser and passkey_hint_browser from a content
// script (the popup has its own path) are sent only right after this tab's top
// frame submitted a login the app answered (capture_browser), or the user saved
// one (save_pending_browser / save_browser, gesture-checked by the app): a
// ticket for that origin, PROBE_TICKET_MS long and PROBE_TICKET_USES requests.
// The ticket only keeps an ordinary page from probing without a submit; it is
// not the limit against a compromised renderer, which can send capture_browser
// itself (no activation needed) and so mint tickets. What bounds that is the
// app's per-origin / per-site probe budget (browser_broker _probe_allowed);
// never rely on the ticket alone.
const PROBE_TICKET_MS = 120000;
const PROBE_TICKET_USES = 4;
const MAX_PROBE_TICKETS = 64;
const SITE_PROBE_TYPES = new Set(["site_logins_browser","passkey_hint_browser"]);
const PROBE_GRANT_TYPES = new Set(["capture_browser","save_pending_browser","save_browser"]);
const probeTickets = new Map();
function grantProbeTicket(tabId, origin) {
  probeTickets.delete(tabId);
  if (probeTickets.size >= MAX_PROBE_TICKETS) probeTickets.delete(probeTickets.keys().next().value);
  probeTickets.set(tabId, {origin, until:Date.now() + PROBE_TICKET_MS, uses:PROBE_TICKET_USES});
}
function takeProbeTicket(tabId, origin) {
  const ticket = probeTickets.get(tabId);
  const now = Date.now();
  if (!ticket || ticket.origin !== origin || now >= ticket.until || now < ticket.until - PROBE_TICKET_MS || ticket.uses <= 0) return false;
  ticket.uses -= 1;
  return true;
}
if (api.tabs?.onRemoved) api.tabs.onRemoved.addListener(tabId => { dropStepUsername(tabId); probeTickets.delete(tabId); });
// "Never for this site": one writer, so near-simultaneous clicks in several
// tabs cannot overwrite each other's entries.
const AUTOMATIC_ORIGIN_KEY = "automatic_save_blocked_origins";
let neverSiteQueue = Promise.resolve();
function blockAutomaticSave(origin) {
  neverSiteQueue = neverSiteQueue.then(async () => {
    const stored = await api.storage.local.get({[AUTOMATIC_ORIGIN_KEY]:[]});
    const list = Array.isArray(stored[AUTOMATIC_ORIGIN_KEY]) ? stored[AUTOMATIC_ORIGIN_KEY] : [];
    if (!list.includes(origin)) await api.storage.local.set({[AUTOMATIC_ORIGIN_KEY]:[...list, origin]});
  }).catch(() => {});
  return neverSiteQueue;
}
function nativeRequest(payload) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r) => { if (!done) { done = true; clearTimeout(timer); resolve(r); } };
    const interactive = ["begin_browser","get_browser","save_browser","save_pending_browser",
      "begin_identity_browser","approve_identity_browser","release_identity_browser",
      "begin_card_browser","approve_card_browser","release_card_browser","begin_totp_browser","get_totp_browser",
      "passkey_create_browser","passkey_get_browser"].includes(payload.action);
    const timeoutMs = interactive ? 90000 : 15000;
    const timer = setTimeout(() => {
      // An approval the user did not answer in time, or a bridge that did not answer.
      finish({ok:false,error:"timeout",message:interactive ? tr("bg_timeout") : tr("popup_diag_timeout")});
      // Close the app's still-open approval dialog (or drop an unconfirmed
      // passkey) so a late approval cannot act on a request the page gave up on.
      const cancel = TIMEOUT_CANCEL[payload.action];
      if (cancel) {
        const out = {action:cancel};
        for (const k of ["origin","context","session_id","grant","passkey_protocol","document_key"]) if (payload[k] !== undefined) out[k] = payload[k];
        Promise.resolve().then(() => api.runtime.sendNativeMessage(HOST_NAME, {...out, protocol:PROTOCOL, extension_version:EXTENSION_VERSION})).catch(() => {});
      }
    }, timeoutMs);
    // Promise form only (Chrome MV3 and Firefox both reject with the lastError text).
    Promise.resolve()
      .then(() => api.runtime.sendNativeMessage(HOST_NAME, {...payload, protocol:PROTOCOL, extension_version:EXTENSION_VERSION}))
      .then(response => {
        if (!response || typeof response !== "object") return finish({ok:false,error:"invalid_native_response"});
        if (!response.ok && response.error === "item_limit") response.message = itemLimitMessage(response.limit);
        else if (!response.ok && readableErrors[response.error]) response.message = readableErrors[response.error];
        finish(response);
      }, error => finish({ok:false,error:"native_host_error",message:hostError(error?.message || "")}));
  });
}
function validText(value, length, empty = false) { return typeof value === "string" && value.length <= length && !value.includes("\0") && (empty || !!value); }
async function frameInfo(tabId, frameId) {
  try { return await api.webNavigation.getFrame({tabId, frameId}); } catch { return null; }
}
function frameOrigin(frame) {
  try { return canonicalOrigin(new URL(frame.url).origin); } catch { return null; }
}
// The sender's frame chain, read from the browser's frame tree (never from
// the page): null when the document is not current (or a frame of the chain
// is unknown or in error), else {crossOrigin, topOrigin}. crossOrigin: some
// ancestor's origin differs from the expected one or cannot be read.
// topOrigin: the top frame's origin, null unless the browser establishes it
// with certainty (every ancestor's origin readable, the tab's URL agreeing).
async function frameChain(sender, expectedOrigin, activeRequired) {
  const tabId = sender.tab.id;
  const frame = await frameInfo(tabId, sender.frameId);
  if (!frame || frame.errorOccurred) return null;
  // Chromium reports the lifecycle; Firefox does not. Only an explicit non-active state rejects.
  if (frame.documentLifecycle !== undefined && frame.documentLifecycle !== "active") return null;
  // Chromium pins the exact document through documentId. Firefox has no
  // documentId on either side; it falls back to the tab + frame-URL origin
  // check below. A documentId present on only one side is a mismatch.
  if (sender.documentId !== undefined || frame.documentId !== undefined) {
    if (!sender.documentId || frame.documentId !== sender.documentId) return null;
  }

  // SPAs such as FACEIT may use history.pushState/replaceState while keeping
  // the same document and login form alive. Path/query/hash changes are not a
  // destination change. The security boundary is the exact origin plus the
  // browser-provided documentId (or, on Firefox, the tab and frame origin).
  if (frameOrigin(frame) !== expectedOrigin) return null;

  let current = frame, frameId = sender.frameId, crossOrigin = false, readable = true, topOrigin = expectedOrigin;
  for (let depth = 0; frameId !== 0; depth++) {
    if (depth >= MAX_FRAME_DEPTH) return null;
    const parentId = current.parentFrameId;
    if (!Number.isInteger(parentId) || parentId < 0) return null;
    const parent = await frameInfo(tabId, parentId);
    if (!parent || parent.errorOccurred) return null;
    const parentOrigin = frameOrigin(parent);
    if (parentOrigin === null) readable = false;
    if (parentOrigin !== expectedOrigin) crossOrigin = true;
    current = parent; frameId = parentId; topOrigin = parentOrigin;
  }

  const tab = await api.tabs.get(tabId);
  if (tab.discarded || (activeRequired && !tab.active)) return null;
  if (crossOrigin) {
    // A second browser source for the top origin: the tab's own URL.
    let tabOrigin = null;
    try { tabOrigin = canonicalOrigin(new URL(tab.url).origin); } catch { /* unreadable */ }
    if (!readable || topOrigin === null || tabOrigin !== topOrigin) topOrigin = null;
  }
  return {crossOrigin, topOrigin};
}
// The sender frame must be the top frame or an iframe whose whole ancestor
// chain (browser-reported, never page-supplied) shares the expected origin.
async function documentStillCurrent(sender, expectedOrigin, activeRequired) {
  const chain = await frameChain(sender, expectedOrigin, activeRequired);
  return !!chain && !chain.crossOrigin;
}
function nudgePendingSave(details) {
  if (!details || !Number.isInteger(details.tabId) || !Number.isInteger(details.frameId) || details.frameId < 0) return;
  try {
    const protocol = new URL(details.url).protocol;
    if (protocol !== "http:" && protocol !== "https:") return;
  } catch { return; }
  // Delivered to the navigated frame only. Frames without our content script
  // (cross-origin ancestry) have no listener; that rejection is expected.
  try {
    const sent = api.tabs.sendMessage(details.tabId,{command:"check_pending_save"},{frameId:details.frameId});
    if (sent && typeof sent.catch === "function") sent.catch(() => {});
  } catch { /* frame or tab already gone */ }
}
api.webNavigation.onDOMContentLoaded?.addListener(nudgePendingSave);
api.webNavigation.onCompleted?.addListener(nudgePendingSave);
api.webNavigation.onHistoryStateUpdated?.addListener(nudgePendingSave);
// Site icons come from the browser's own favicon cache (the "favicon"
// permission), so saving one never makes a network request. Chrome answers
// unknown pages with a generic globe; that one is skipped. Firefox has no
// _favicon endpoint and the permission is stripped from its manifest: the
// payload then carries no site_icon and the desktop app shows its neutral icon.
let genericIcon = null;
function faviconSupported() {
  try { return (api.runtime.getManifest().permissions || []).includes("favicon") && !globalThis.browser; }
  catch { return false; }
}
async function faviconBytes(pageUrl) {
  const url = new URL(api.runtime.getURL("/_favicon/"));
  url.searchParams.set("pageUrl", pageUrl);
  url.searchParams.set("size", "64");
  const response = await fetch(url.toString());
  if (!response.ok) return null;
  const bytes = new Uint8Array(await response.arrayBuffer());
  return bytes.length > 0 && bytes.length <= 48 * 1024 ? bytes : null;
}
function sameBytes(a, b) {
  return !!a && !!b && a.length === b.length && a.every((value, index) => value === b[index]);
}
async function siteIcon(pageUrl) {
  if (!faviconSupported()) return null;
  try {
    const bytes = await faviconBytes(pageUrl);
    // PNG signature check; anything else is ignored.
    if (!bytes || bytes[0] !== 0x89 || bytes[1] !== 0x50 || bytes[2] !== 0x4e || bytes[3] !== 0x47) return null;
    if (genericIcon === null) genericIcon = (await faviconBytes("https://localgatekeys.invalid/")) || new Uint8Array();
    if (sameBytes(bytes, genericIcon)) return null;
    let binary = "";
    for (const value of bytes) binary += String.fromCharCode(value);
    return btoa(binary);
  } catch {
    return null;
  }
}
// The bundled site-logo set (scripts/build_site_logos.mjs), loaded once and
// only when a picker opens. A host matches a listed domain or any subdomain of
// it, so a lookalike host (google.com.example.net) never gets the brand's logo.
let siteLogos = null;
async function siteLogo(origin) {
  try {
    if (siteLogos === null) siteLogos = await (await fetch(api.runtime.getURL("site-logos.json"))).json();
    const labels = new URL(origin).hostname.toLowerCase().replace(/\.$/, "").split(".");
    for (let i = 0; i < labels.length - 1; i++) {
      const slug = siteLogos.domains[labels.slice(i).join(".")];
      const logo = slug && siteLogos.logos[slug];
      if (logo) return {title: logo.title, hex: logo.hex, path: logo.path};
    }
  } catch { /* no logo: the picker shows plain rows */ }
  return null;
}

// ---- Phishing shield. The app compares the page origin with the saved
// origins (which never leave it) and answers a verdict. Only that verdict is
// passed on, cleaned. When the app cannot answer (locked vault, older app),
// the bundled classifier still flags a host that mixes scripts: that check
// needs no saved origin. Nothing here makes a network request; the suffix
// list is the packaged psl-min.json.
const VERDICT_KINDS = new Set(["exact","related","lookalike","unknown"]);
let lookalikeRules = null;
async function localVerdict(origin) {
  if (typeof LGKLookalike === "undefined") return null;
  if (lookalikeRules === null) {
    lookalikeRules = fetch(api.runtime.getURL("psl-min.json")).then(r => r.json()).then(data => { LGKLookalike.setRules(data); return true; })
      .catch(() => { lookalikeRules = null; return false; });
  }
  try { return (await lookalikeRules) ? LGKLookalike.classify(origin, []) : null; } catch { return null; }
}
async function siteVerdictReply(response, origin) {
  if (response?.ok && VERDICT_KINDS.has(response.kind)) {
    const out = {ok:true, kind:response.kind, reason:typeof response.reason === "string" ? response.reason.slice(0, 32) : ""};
    if (response.kind === "lookalike") {
      out.matched = typeof response.matched === "string" && response.matched.length <= 253 && /^[!-~]+$/.test(response.matched) ? response.matched : null;
      if (typeof response.pair === "string" && /^[0-9a-f]{32}$/.test(response.pair)) out.pair = response.pair;
    }
    return out;
  }
  const local = await localVerdict(origin);
  if (local?.kind === "lookalike") return {ok:true, kind:"lookalike", reason:local.reason, matched:null, local:true};
  return {ok:true, locked:response?.locked === true, unchecked:true};
}

// ---- Panel relay. content.js draws its pickers, guards and prompts in
// panel.html, an extension page it frames into the page, so that no vault
// text is in DOM the page can read or search. The frame asks for what to draw
// and reports clicks here; this worker hands each request, with the frame's
// browser-reported id and document, to the content script of the same tab
// (the frame's parent where the browser reports it). The content script
// answers only the random token it gave that frame, and only for the first
// frame that presented it. Nothing here comes from the page: pages cannot
// message the extension, and the sender must be our own panel page.
const PANEL_TYPES = Object.freeze({__proto__:null, ui_pull:"pull", ui_size:"size", ui_event:"event"});
const UI_TOKEN = /^[0-9a-f]{32}$/;
const UI_ID = /^[a-z0-9_-]{1,32}$/;
function panelFrameSender(sender) {
  if (!sender.tab || !Number.isInteger(sender.tab.id) || !Number.isInteger(sender.frameId) || sender.frameId <= 0 || typeof sender.url !== "string") return false;
  try {
    const url = new URL(sender.url), own = new URL(api.runtime.getURL("panel.html"));
    // use_dynamic_url (Chromium) gives the frame a per-session host, so the
    // scheme and path are what identify our page; sender.id is checked above.
    return url.protocol === own.protocol && url.pathname === own.pathname;
  } catch { return false; }
}
// Only the fields the content script reads, each type-checked.
function panelMessage(request) {
  if (!UI_TOKEN.test(request.token ?? "")) return null;
  const op = PANEL_TYPES[request.type];
  const out = {command:"ui", op, token:request.token};
  if (op === "size") {
    if (typeof request.height !== "number" || !Number.isFinite(request.height) || request.height < 0 || request.height > 4000) return null;
    out.height = request.height;
  } else if (op === "event") {
    if (!UI_ID.test(request.id ?? "")) return null;
    out.id = request.id;
    if (request.id === "__escape") return out;
    for (const key of ["x", "y"]) {
      if (typeof request[key] !== "number" || !Number.isFinite(request[key])) return null;
      out[key] = request[key];
    }
    if (!Number.isInteger(request.detail) || request.detail < 0) return null;
    out.detail = request.detail;
    if (request.visible !== null && typeof request.visible !== "boolean") return null;
    out.visible = request.visible;
    const checks = request.checks ?? {};
    if (!checks || typeof checks !== "object" || Array.isArray(checks)) return null;
    const entries = Object.entries(checks);
    if (entries.length > 32 || entries.some(([k, v]) => !UI_ID.test(k) || typeof v !== "boolean")) return null;
    out.checks = Object.fromEntries(entries);
    if (request.value !== undefined) {
      // The generator's suggestion, or the save panel's edited username.
      if (!validText(request.value, 512, true)) return null;
      out.value = request.value;
    }
  }
  return out;
}
async function panelRelay(request, sender) {
  if (!panelFrameSender(sender)) return {ok:false,error:"untrusted_sender"};
  const message = panelMessage(request);
  if (!message) return {ok:false,error:"invalid_request"};
  message.frame = {id:sender.frameId, document:typeof sender.documentId === "string" ? sender.documentId : null};
  const tabId = sender.tab.id;
  const parent = (await frameInfo(tabId, sender.frameId))?.parentFrameId;
  try {
    const reply = Number.isInteger(parent) && parent >= 0
      ? await api.tabs.sendMessage(tabId, message, {frameId:parent})
      : await api.tabs.sendMessage(tabId, message);
    return reply && typeof reply === "object" ? reply : {ok:false};
  } catch { return {ok:false}; }
}

// site_logins_browser: {ok, logins:[{entry_id, title, username}]}, at most 20,
// each field a bounded string. Anything else (older app: unknown command,
// locked vault) is "unsupported" or "locked", and callers degrade.
const MAX_SITE_LOGINS = 20;
function siteLoginsReply(response) {
  if (response?.ok !== true || !Array.isArray(response.logins)) return {ok:false, error:response?.error === "locked" || response?.locked === true ? "locked" : "unsupported"};
  const logins = [];
  for (const l of response.logins.slice(0, MAX_SITE_LOGINS)) {
    if (!l || !validText(l.entry_id,128) || !validText(l.title ?? "",256,true) || !validText(l.username ?? "",512,true)) continue;
    logins.push({entry_id:l.entry_id, title:l.title ?? "", username:l.username ?? ""});
  }
  return {ok:true, logins};
}
async function popupSiteLogins() {
  try {
    const [tab] = await api.tabs.query({active:true, currentWindow:true});
    const url = new URL(tab?.url || "");
    if (!tab || !Number.isInteger(tab.id) || !["https:","http:"].includes(url.protocol)) return {ok:false, error:"unsupported_page"};
    const origin = canonicalOrigin(url.origin);
    const context = JSON.stringify([tab.id,"popup",origin,crypto.randomUUID()]);
    const reply = siteLoginsReply(await nativeRequest({action:"site_logins_browser", origin, context}));
    // The tab may have moved on while the app answered.
    const [now] = await api.tabs.query({active:true, currentWindow:true});
    try { if (!now || now.id !== tab.id || canonicalOrigin(new URL(now.url).origin) !== origin) return {ok:false, error:"destination_changed"}; } catch { return {ok:false, error:"destination_changed"}; }
    return reply.ok ? {...reply, origin} : reply;
  } catch { return {ok:false, error:"unsupported"}; }
}
api.runtime.onMessage.addListener((request, sender, sendResponse) => {
  (async () => {
    if (!request || typeof request !== "object" || sender.id !== api.runtime.id) return {ok:false,error:"untrusted_sender"};
    // Only the packaged extension popup can request diagnostics without a tab.
    if (!sender.tab && sender.url === api.runtime.getURL("popup.html") && request.type === "diagnostics") {
      const r = await nativeRequest({action:"ping"});
      return {...r,extension_version:EXTENSION_VERSION};
    }
    // The panel frame (panel.html, framed into a page by content.js).
    if (PANEL_TYPES[request.type]) return panelRelay(request, sender);
    // The popup's login list for the active tab's top frame. The origin comes
    // from the browser's tab, never from the request; titles and usernames
    // only, never a secret. An app without the command answers unsupported.
    if (!sender.tab && sender.url === api.runtime.getURL("popup.html") && request.type === "site_logins") return popupSiteLogins();
    // Any frame may ask; frameChain verifies it against the browser's frame
    // tree (same-origin ancestry up to the top frame; a passkey get alone may
    // come from a frame of another site, see below).
    if (!sender.tab || !Number.isInteger(sender.tab.id) || !Number.isInteger(sender.frameId) || sender.frameId < 0 || typeof sender.url !== "string") return {ok:false,error:"untrusted_sender"};
    const origin = canonicalOrigin(new URL(sender.url).origin);
    if (origin !== canonicalOrigin(request.origin)) return {ok:false,error:"origin_mismatch"};
    if (!senderOriginOk(sender, origin)) return {ok:false,error:"origin_mismatch"};
    if (!validText(request.operation_id, 128)) return {ok:false,error:"invalid_request"};
    // The site's login list and the passkey hint are for the top frame only.
    if (SITE_PROBE_TYPES.has(request.type) && sender.frameId !== 0) return {ok:false,error:"destination_changed",message:readableErrors.destination_changed};
    if (SITE_PROBE_TYPES.has(request.type) && !takeProbeTicket(sender.tab.id, origin)) return {ok:false,error:"user_gesture_required"};
    if (["step_username_browser","recall_username_browser","never_site_browser"].includes(request.type)) {
      const chain = await frameChain(sender, origin, false);
      if (!chain || chain.crossOrigin) return {ok:false,error:"destination_changed",message:readableErrors.destination_changed};
      const tabId = sender.tab.id;
      if (request.type === "never_site_browser") { await blockAutomaticSave(origin); return {ok:true}; }
      if (request.type === "step_username_browser") {
        if (!validText(request.username,512)) return {ok:false,error:"invalid_credential"};
        await keepStepUsername(tabId, {origin, username:request.username, at:Date.now()});
        return {ok:true};
      }
      const kept = await takeStepUsername(tabId);
      const fresh = kept && kept.origin === origin && typeof kept.username === "string" && Number.isFinite(kept.at) &&
        Date.now() - kept.at <= STEP_USERNAME_MS && Date.now() >= kept.at;
      return {ok:true, username: fresh ? kept.username : ""};
    }
    const allowed = new Set(["site_logins_browser","passkey_hint_browser","ping","begin_browser","begin_gesture_browser","get_browser","validate_browser","submit_browser","cancel_browser","check_browser","save_browser","capture_browser","pending_browser","save_pending_browser","discard_pending_browser","clear_pending_browser","begin_identity_browser","approve_identity_browser","release_identity_browser","cancel_identity_browser","begin_card_browser","approve_card_browser","release_card_browser","cancel_card_browser","begin_totp_browser","get_totp_browser","passkey_create_browser","passkey_get_browser","passkey_confirm_browser","passkey_discard_browser","classify_site_browser","new_site_username_browser","fill_grant_browser"]);
    if (!allowed.has(request.type)) return {ok:false,error:"unsupported_request"};
    const activeRequired = !["ping","cancel_browser","check_browser","capture_browser","pending_browser","discard_pending_browser","clear_pending_browser","classify_site_browser","passkey_confirm_browser","passkey_discard_browser"].includes(request.type);
    const passkeyOutcome = PASSKEY_OUTCOME_TYPES.has(request.type);
    // A confirm or discard is sent while the page may already be leaving (a
    // site often navigates as soon as it has the credential), so it is not
    // held to the current document: its context must equal the create's
    // exactly, which only that create's own document can produce.
    // Known limitation 4: a passkey get (only) may come from a frame of
    // another site. Its top origin comes from the browser's frame tree and
    // the tab, never from the message. The frame's permissions policy
    // (publickey-credentials-get, read by webauthn-bridge.js in the isolated
    // world) can only send the request to the browser, never admit one; an
    // unreadable policy or top origin does the same. A create, and every
    // other action, from such a frame is refused as before.
    let topOrigin = null;
    if (!passkeyOutcome) {
      const chain = await frameChain(sender, origin, activeRequired);
      if (!chain || (chain.crossOrigin && request.type !== "passkey_get_browser")) return {ok:false,error:"destination_changed",message:readableErrors.destination_changed};
      if (chain.crossOrigin) {
        if (request.publickey_get_policy !== "allowed" || !chain.topOrigin) return {ok:false,error:"fallback"};
        topOrigin = chain.topOrigin;
      }
    }
    // Browser-derived document identity, never caller-supplied tab/frame IDs.
    // Firefox has no documentId; the frame id plus the random per-document key
    // content.js (fills and saves) or webauthn-bridge.js (passkeys) draws when
    // it loads stand in, so that two frames of one tab, or two documents loaded
    // one after the other in one frame, never share a context. Pages cannot
    // message the extension, so the key comes from our own content script.
    const documentKey = sender.documentId ?? (typeof request.document_key === "string" && DOCUMENT_KEY.test(request.document_key)
      ? `frame:${sender.frameId}:${request.document_key}` : `frame:${sender.frameId}`);
    // A cross-origin get binds the top origin as a fifth element, so an
    // approval under one top site never serves another. Every other request
    // keeps the four-element context.
    const context = JSON.stringify(topOrigin ? [sender.tab.id,documentKey,origin,request.operation_id,topOrigin]
      : [sender.tab.id,documentKey,origin,request.operation_id]);
    const payload = {action:request.type,origin,context};
    if (passkeyOutcome) {
      // Nothing else is forwarded, and the page learns only that the message went.
      if (request.passkey_protocol !== PASSKEY_PROTOCOL) return {ok:false,error:"version_mismatch"};
      await nativeRequest({...payload, passkey_protocol:PASSKEY_PROTOCOL});
      return {ok:true};
    }
    if (URL_ACTIONS.has(request.type) && request.url !== undefined && request.url !== null) {
      const url = pageUrlFor(request.url, origin);
      if (url !== undefined) payload.url = url;
    }
    if (PASSKEY_TYPES.has(request.type)) {
      // WebAuthn options are page data. The broker parses and bounds every
      // field; here only the protocol pin and the overall size are checked.
      // "fallback" makes webauthn-page.js use the browser's own authenticator.
      // The app's "system_provider" (Windows passkey provider on and
      // registered) is returned unchanged below like every other reply: the
      // page then calls the browser's own create/get at once so Windows routes
      // it to the provider. Only the app can answer it; a page cannot.
      if (request.passkey_protocol !== PASSKEY_PROTOCOL) return {ok:false,error:"version_mismatch",message:readableErrors.version_mismatch};
      const options = request.options;
      let size = Infinity;
      try { size = JSON.stringify(options).length; } catch { /* cyclic or unserializable */ }
      if (!options || typeof options !== "object" || Array.isArray(options) || !(size <= MAX_PASSKEY_OPTIONS)) return {ok:false,error:"fallback"};
      payload.passkey_protocol = PASSKEY_PROTOCOL;
      payload.options = options;
      // Read by webauthn-bridge.js in the isolated world, not by the page;
      // the broker refuses a create without it.
      payload.user_activation = request.user_activation === true;
      // This extension confirms or discards every create (webauthn-page.js,
      // webauthn-bridge.js), so the app may save it unconfirmed. Set here,
      // never taken from the request.
      if (request.type === "passkey_create_browser") payload.passkey_confirm = true;
      // Set only after the checks above; the app refuses a top origin the context does not bind.
      if (topOrigin) { payload.top_origin = topOrigin; payload.publickey_get_allowed = true; }
    }
    const identityAction = request.type.endsWith("_identity_browser");
    const cardAction = request.type.endsWith("_card_browser");
    if (cardAction) {
      // Same shape as identity: protocol pin, typed token list, revision and
      // approval are validated here; values never pass through this worker
      // except inside the broker's release reply.
      if (request.card_protocol !== CARD_FILL_PROTOCOL) return {ok:false,error:"version_mismatch",message:readableErrors.version_mismatch};
      payload.card_protocol=CARD_FILL_PROTOCOL;
      if (request.fields !== undefined) {
        if (!Array.isArray(request.fields) || request.fields.length < 1 || request.fields.length > CARD_FIELDS.size ||
            request.fields.some(field => typeof field !== "string" || !CARD_FIELDS.has(field)) ||
            new Set(request.fields).size !== request.fields.length) return {ok:false,error:"invalid_card_fields",message:readableErrors.invalid_card_fields};
        payload.fields=[...request.fields];
      }
      if (request.revision !== undefined && (!Number.isInteger(request.revision) || request.revision < 1)) return {ok:false,error:"invalid_request"};
      if (request.revision !== undefined) payload.revision=request.revision;
      if (request.approval !== undefined) {
        if (!validText(request.approval,128)) return {ok:false,error:"invalid_approval"};
        payload.approval=request.approval;
      }
    }
    if (identityAction) {
      if (request.identity_protocol !== IDENTITY_FILL_PROTOCOL) return {ok:false,error:"version_mismatch"};
      payload.identity_protocol=IDENTITY_FILL_PROTOCOL;
      const identityFields = new Set(["name","given_name","middle_name","family_name","organization","company","job_title","email","phone","address","address_line1","address_line2","city","state","postal_code","country","website"]);
      if (request.fields !== undefined) {
        if (!Array.isArray(request.fields) || request.fields.length < 1 || request.fields.length > 16 ||
            request.fields.some(field => typeof field !== "string" || !identityFields.has(field)) ||
            new Set(request.fields).size !== request.fields.length) return {ok:false,error:"invalid_identity_fields"};
        payload.fields=[...request.fields];
      }
      if (request.revision !== undefined && (!Number.isInteger(request.revision) || request.revision < 1)) return {ok:false,error:"invalid_request"};
      if (request.revision !== undefined) payload.revision=request.revision;
      if (request.approval !== undefined) {
        if (!validText(request.approval,128)) return {ok:false,error:"invalid_approval"};
        payload.approval=request.approval;
      }
    }
    if (["save_browser","check_browser","capture_browser"].includes(request.type)) {
      if (!validText(request.username,512,true) || !validText(request.password,4096)) return {ok:false,error:"invalid_credential"};
      payload.username=request.username; payload.password=request.password;
    }
    // Save panel: the username the user edited there replaces the captured one.
    if (request.type === "save_pending_browser" && request.username !== undefined) {
      if (!validText(request.username,512)) return {ok:false,error:"invalid_credential"};
      payload.username=request.username;
    }
    if (request.type === "new_site_username_browser") {
      // Ruling T4b: only the username the user typed and submitted; the app
      // answers whether it is saved for another site, never which one.
      if (!validText(request.username,512)) return {ok:false,error:"invalid_credential"};
      payload.username=request.username;
    }
    if (request.entry_id !== undefined) {
      if (!validText(request.entry_id,128)) return {ok:false,error:"invalid_entry_id"};
      payload.entry_id=request.entry_id;
    }
    if (request.grant !== undefined) {
      if (!validText(request.grant,128)) return {ok:false,error:"invalid_grant"};
      payload.grant=request.grant;
    }
    if (request.session_id !== undefined && request.session_id !== null) {
      if (!validText(request.session_id,128)) return {ok:false,error:"invalid_session"};
      payload.session_id=request.session_id;
    }
    if (request.pending_token !== undefined) {
      if (!validText(request.pending_token,128)) return {ok:false,error:"invalid_pending_token"};
      payload.pending_token=request.pending_token;
    }
    // Broker-issued gesture nonce (begin_browser / begin_totp_browser /
    // begin_gesture_browser): 32 hex characters, forwarded verbatim. The
    // broker binds it to this origin and context, so nothing else is checked here.
    if (request.gesture_nonce !== undefined && request.gesture_nonce !== null) {
      if (typeof request.gesture_nonce !== "string" || !/^[0-9a-f]{32}$/.test(request.gesture_nonce)) return {ok:false,error:"invalid_gesture_nonce"};
      payload.gesture_nonce=request.gesture_nonce;
    }
    payload.user_gesture=request.user_gesture===true;
    // The user answered the lookalike guard in our closed-shadow panel; the
    // app classifies again and still asks in its own dialog (review R1).
    if (["save_browser","save_pending_browser"].includes(request.type) && request.lookalike_confirmed === true) payload.lookalike_confirmed=true;
    payload.username_only=request.username_only===true;
    if (["save_browser","save_pending_browser","get_browser","capture_browser"].includes(request.type)) {
      const icon = await siteIcon(sender.url);
      if (icon) payload.site_icon = icon;
    }
    const response = await nativeRequest(payload);
    // A top-frame capture the app answered grants the ticket even when the
    // page navigated before the reply (a classic POST change-password form):
    // the next page of this origin then offers the update. The ticket is for
    // the origin the capture was typed on (checked against the browser's
    // frame tree before the request), never the origin the tab moved to, and
    // frame 0 only, so a cross-origin frame never grants one.
    const captureGrant = request.type === "capture_browser" && sender.frameId === 0 && response?.ok === true;
    if (captureGrant) grantProbeTicket(sender.tab.id, origin);
    // Drop late replies if navigation/tab switching changed the destination
    // (for a cross-origin get: also if the top site changed).
    const after = await frameChain(sender,origin,activeRequired);
    if (!after || (topOrigin ? !after.crossOrigin || after.topOrigin !== topOrigin : after.crossOrigin)) {
      // A created passkey that is dropped here never reaches the page: the
      // app removes the copy it saved unconfirmed.
      if (request.type === "passkey_create_browser" && response?.ok === true) {
        nativeRequest({action:"passkey_discard_browser",origin,context,passkey_protocol:PASSKEY_PROTOCOL});
      }
      return {ok:false,error:"destination_changed",message:readableErrors.destination_changed};
    }
    if (!captureGrant && PROBE_GRANT_TYPES.has(request.type) && sender.frameId === 0 && response?.ok === true) grantProbeTicket(sender.tab.id, origin);
    if (request.type === "classify_site_browser") return siteVerdictReply(response, origin);
    if (request.type === "new_site_username_browser") return response?.ok ? {ok:true, elsewhere:response.elsewhere === true} : {ok:false, error:"unavailable"};
    if (request.type === "site_logins_browser") return siteLoginsReply(response);
    if (request.type === "passkey_hint_browser") return response?.ok === true ? {ok:true, supported:response.supported === true, has_passkey:response.has_passkey !== false} : {ok:false, error:"unsupported"};
    // Login and 2FA pickers list accounts for this page's own origin: draw its logo.
    if (response?.ok && Array.isArray(response.choices) && ["begin_browser","begin_totp_browser"].includes(request.type)) {
      const logo = await siteLogo(origin);
      if (logo) response.site_logo = logo;
    }
    return response;
  })().then(sendResponse).catch(() => sendResponse({ok:false,error:"internal_error",message:tr("bg_host_failed")}));
  return true;
});
// Keyboard shortcut (manifest "commands"): the same fill as the popup's
// button, in the active tab's top frame; the content script keeps every check.
if (api.commands?.onCommand) api.commands.onCommand.addListener(async command => {
  if (command !== "fill-login") return;
  try {
    const [tab] = await api.tabs.query({active:true, currentWindow:true});
    if (tab && Number.isInteger(tab.id)) await api.tabs.sendMessage(tab.id, {command:"fill_current"}, {frameId:0});
  } catch {}
});
