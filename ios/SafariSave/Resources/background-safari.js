"use strict";
// Safari on iPhone: non-persistent background page, loaded after api.js
// (see build-safari-extension.cjs). It does in the extension what the desktop
// broker does in process memory for the save prompt, and nothing else: the
// extension cannot fill, read the vault, or see the master password. The one
// exception is an AI agent's sign-in the user approved in the Mac app, released
// by the user's own clicks (see OFFER_TTL_MS below).
//
// Classification and saving go to the app's Safari extension handler with
// sendNativeMessage("app.localgatekeys.app", {action, origin, username,
// password[, status]}). Pending captures live only in this page's memory:
// when Safari unloads it, they are lost (no prompt), and a password is never
// written to extension storage. A capture is bound to the document it was
// typed in (documentId, else the content script's random per-document key)
// and lives 90 s, like the desktop broker's.
const NATIVE_APP_ID = "app.localgatekeys.app";
const PENDING_TTL_MS = 90000;
const GESTURE_TTL_MS = 30000;
const NATIVE_TIMEOUT_MS = 15000;
const MAX_GESTURES = 64;
// A sign-in that lands on another subdomain of the same site (login.paddle.com
// to vendors.paddle.com) may show the capture there for this long after it was
// made, like the desktop broker's redirect grace. The native handler decides
// "same site" with the Public Suffix List.
const HANDOFF_MS = 12000;
// capture_browser / check_browser compare a page-supplied password with the
// stored one without a gesture (they run on form submit), so, as on the
// desktop, they must not become a guessing oracle: at most PROBE_PER_ORIGIN
// per origin per minute, PROBE_TOTAL per minute overall as a backstop, with a
// small reserved share per origin so one busy site cannot silence the others,
// and a hard ceiling that bounds memory.
const PROBE_WINDOW_MS = 60000;
const PROBE_PER_ORIGIN = 10;
const PROBE_TOTAL = 30;
const PROBE_RESERVE = 3;
const PROBE_HARD = 120;
const DOCUMENT_KEY = /^[0-9a-f]{32}$/;
const MAX_FRAME_DEPTH = 32;
const SAVE_ERRORS = {
  get full() { return tr("bg_full_notice"); },
  get inbox_full() { return tr("bg_save_inbox_full"); },
  get invalid() { return tr("bg_save_invalid"); },
  get unavailable() { return tr("bg_save_unavailable"); },
};
// The app's classify answers only "new", "exists", "full" or "unavailable":
// it never tells the extension (or the page) whether a password matches the
// saved one. Passwords are compared inside the app at import, after the user
// confirms there. "exists" prompts a neutral save-or-update; "unavailable"
// (and anything else) means no prompt.
const PROMPT_STATUSES = new Set(["new", "exists", "full"]);
// The iPhone app also answers "filled" when its AutoFill extension has just
// filled this site and username from LocalGateKeys (then for a few seconds
// more, for a repeated capture of the same submit; the answer never depends
// on the password). It means: nothing to offer. No prompt, no pending capture, no badge,
// and the page gets the same answer as for "unavailable". It is kept out of
// PROMPT_STATUSES on purpose, so an edit of that set cannot make it a prompt.
const FILLED_STATUS = "filled";
const HANDLED = new Set(["status", "capture_browser", "pending_browser", "save_pending_browser", "discard_pending_browser",
  "clear_pending_browser", "check_browser", "save_browser", "begin_gesture_browser", "classify_site_browser",
  "agent_status_browser", "fill_grant_browser", "get_browser", "validate_browser", "cancel_browser", "never_site_browser"]);
// AI agent sign-in (Mac, Settings > Developer > "Allow AI agents to use
// LocalGateKeys"). The one exception to "Safari never fills": after the user
// approved an agent's sign-in in the app, the user's own click on the field
// icon asks for it (fill_grant_browser), the approved logins open in the
// picker, and a second click there releases the one picked (get_browser, with
// a gesture nonce). The app arms the grant for the approved host only and uses
// it up on the first ask. get_browser and validate_browser answer
// "unsupported" unless an offer from fill_grant_browser for this tab, origin
// and document is waiting: there is no other fill on Safari.
const OFFER_TTL_MS = 60000;
const MAX_OFFERS = 8;
const AGENT_STATUS_TTL_MS = 10000;

// `${tabId}|${origin}` -> {token, origin, username, password, status, created, doc}; at most one per tab.
const pending = new Map();
// gesture nonce -> {key, doc, operation_id, expires}; single use.
const gestures = new Map();
// offer token -> {key, doc, native, entries: Set, expires, released: entry id | null}; one release each.
const offers = new Map();
let agentStatus = { at: -Infinity, agent: false };
// Toolbar button (popup-safari.html). The popup never lists or fills logins:
// filling stays with Safari AutoFill. It shows how many captures wait in the
// app's Safari inbox (pending_count answers a number only: no site, username
// or password), switches the save prompt for the tab's site, and on the Mac
// asks the native handler to open the app (open_app). Whether the button shows
// comes from the native handler too (open_app_supported: the Mac answers
// supported, the iPhone unsupported), as can_open in popup_state_safari.
const POPUP_PAGE = "popup-safari.html";
// The per-site "Never on this site" list content.js reads (and desktop shares).
const AUTOMATIC_ORIGIN_KEY = "automatic_save_blocked_origins";
const MAX_BLOCKED_ORIGINS = 2000;
const BADGE_TTL_MS = 30000;
const BADGE_MAX = 999;
let badge = { at: -Infinity, count: 0 };
// pending_count requests sent / the newest one whose answer is on the badge:
// an older answer that arrives late never replaces a newer one.
let badgeSent = 0, badgeShown = 0;
let neverSiteQueue = Promise.resolve();
// [time, origin] of recent password comparisons.
let probes = [];

function canonicalOrigin(value) {
  const u = new URL(value);
  if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) throw new Error("Expected an origin");
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new Error("Use HTTPS (or local test pages)");
  return u.origin;
}
function senderOrigin(url) {
  try { return canonicalOrigin(new URL(url).origin); } catch { return null; }
}
function validText(value, length, empty = false) { return typeof value === "string" && value.length <= length && !value.includes("\0") && (empty || !!value); }
function randomHex() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}
function sweep(now) {
  for (const [key, entry] of pending) if (now - entry.created >= PENDING_TTL_MS || now < entry.created - PENDING_TTL_MS) pending.delete(key);
  for (const [nonce, g] of gestures) if (now >= g.expires) gestures.delete(nonce);
  for (const [token, o] of offers) if (now >= o.expires) offers.delete(token);
}
// The waiting agent offer this document may act on, else null.
function offerFor(request, key, doc, now) {
  const token = request.grant;
  if (typeof token !== "string" || !/^[0-9a-f]{32}$/.test(token)) return null;
  const offer = offers.get(token);
  if (!offer || offer.key !== key || offer.doc !== doc || now >= offer.expires) return null;
  return { token, offer };
}
function probeAllowed(origin, now) {
  probes = probes.filter(([at]) => now - at < PROBE_WINDOW_MS && now >= at);
  const own = probes.filter(([, seen]) => seen === origin).length;
  if (own >= PROBE_PER_ORIGIN || probes.length >= PROBE_HARD) return false;
  if (probes.length >= PROBE_TOTAL && own >= PROBE_RESERVE) return false;
  probes.push([now, origin]);
  return true;
}
// The document a message comes from: the browser's documentId where Safari
// reports one, else the key content.js drew for its document.
function documentOf(request, sender) {
  if (typeof sender.documentId === "string" && sender.documentId) return `doc:${sender.documentId}`;
  return typeof request.document_key === "string" && DOCUMENT_KEY.test(request.document_key) ? `key:${request.document_key}` : "";
}
// A capture made in another document of this tab is offered only within
// HANDOFF_MS of being made (a sign-in that posts and lands on a new page);
// later it is dropped rather than left to any later document.
function boundTo(key, entry, doc, now) {
  if (entry.doc === doc) return true;
  if (now - entry.created >= HANDOFF_MS || now < entry.created) { pending.delete(key); return false; }
  entry.doc = doc;
  return true;
}
function frameOrigin(frame) { return frame && !frame.errorOccurred ? senderOrigin(frame.url) : null; }
// Every frame from the sender up to the top must have the sender's origin.
// With webNavigation (requested in the Safari manifest) the whole chain is
// checked through getFrame; if the API is missing, only the tab's top document can be compared. content.js refuses
// to run below a cross-origin ancestor in either case.
async function frameChainOk(sender, origin) {
  if (sender.frameId === undefined || sender.frameId === 0) return true;
  if (typeof sender.tab.url !== "string" || senderOrigin(sender.tab.url) !== origin) return false;
  const getFrame = api.webNavigation?.getFrame;
  if (typeof getFrame !== "function") return true;
  try {
    let frameId = sender.frameId;
    for (let depth = 0; frameId !== 0; depth++) {
      if (depth >= MAX_FRAME_DEPTH) return false;
      const frame = await api.webNavigation.getFrame({ tabId: sender.tab.id, frameId });
      if (frameOrigin(frame) !== origin) return false;
      const parentId = frame.parentFrameId;
      if (!Number.isInteger(parentId) || parentId < 0) return parentId === -1 && frameId === 0;
      frameId = parentId;
    }
    return frameOrigin(await api.webNavigation.getFrame({ tabId: sender.tab.id, frameId: 0 })) === origin;
  } catch { return false; }
}
function dropTab(tabId) {
  const prefix = `${tabId}|`;
  for (const key of pending.keys()) if (key.startsWith(prefix)) pending.delete(key);
}
// One writer for the blocked-site list, so two tabs (or a tab and the popup)
// never drop each other's entries. At MAX_BLOCKED_ORIGINS a new site is
// refused ({ok: false, error: "full"}) and the list is kept as it is: no
// older site silently gets its save prompt back.
function setAutomaticSave(origin, enabled) {
  const run = neverSiteQueue.then(async () => {
    const stored = await api.storage.local.get({ [AUTOMATIC_ORIGIN_KEY]: [] });
    const list = Array.isArray(stored[AUTOMATIC_ORIGIN_KEY]) ? stored[AUTOMATIC_ORIGIN_KEY].filter(o => typeof o === "string") : [];
    if (!enabled && !list.includes(origin) && list.length >= MAX_BLOCKED_ORIGINS) return { ok: false, error: "full" };
    const next = enabled ? list.filter(o => o !== origin) : (list.includes(origin) ? list : [...list, origin]);
    if (next.length !== list.length || next.some((o, i) => o !== list[i])) await api.storage.local.set({ [AUTOMATIC_ORIGIN_KEY]: next });
    return { ok: true };
  });
  neverSiteQueue = run.catch(() => {});
  return run.catch(() => ({ ok: false, error: "unavailable" }));
}
async function automaticSaveEnabled(origin) {
  try {
    const stored = await api.storage.local.get({ [AUTOMATIC_ORIGIN_KEY]: [] });
    return !(Array.isArray(stored[AUTOMATIC_ORIGIN_KEY]) && stored[AUTOMATIC_ORIGIN_KEY].includes(origin));
  } catch { return false; }
}
// Logins waiting in the Safari inbox, as the app's handler counts them (0 on
// any doubt: no keys, an erase pending, a duress session).
async function pendingCount() {
  const r = await native({ action: "pending_count" });
  const text = typeof r?.count === "string" ? r.count : "";
  const n = /^[0-9]{1,6}$/.test(text) ? Number(text) : 0;
  return Math.min(n, BADGE_MAX);
}
function badgeSupported() { return typeof api.action?.setBadgeText === "function"; }
function showBadge(count) {
  if (!badgeSupported()) return;
  const action = api.action;
  try {
    const set = action.setBadgeText({ text: count > 0 ? String(count) : "" });
    if (set && typeof set.catch === "function") set.catch(() => {});
    const color = action.setBadgeBackgroundColor?.({ color: "#1F6FE5" });
    if (color && typeof color.catch === "function") color.catch(() => {});
  } catch { /* no badge on this Safari */ }
}
async function refreshBadge(force = false) {
  const now = Date.now();
  if (!force && now - badge.at < BADGE_TTL_MS && now >= badge.at) return badge.count;
  badge = { at: now, count: badge.count };
  const seq = ++badgeSent;
  const count = await pendingCount();
  // A newer request already answered: this reply is older than the badge.
  if (seq < badgeShown) return badge.count;
  badgeShown = seq;
  badge = { at: Date.now(), count };
  showBadge(count);
  return count;
}
function fromPopup(sender) {
  if (!sender || sender.id !== api.runtime.id || sender.tab || typeof sender.url !== "string") return false;
  if (typeof api.runtime.getURL !== "function") return false;
  return sender.url.split(/[?#]/)[0] === api.runtime.getURL(POPUP_PAGE);
}
async function handlePopup(request) {
  switch (request.type) {
    case "popup_state_safari": {
      let origin = null;
      try { origin = canonicalOrigin(request.origin); } catch { /* not a site the extension saves for */ }
      const [count, canOpen] = await Promise.all([refreshBadge(true), native({ action: "open_app_supported" })]);
      // Only an explicit true from the native handler shows "Open LocalGateKeys" (the Mac's).
      const reply = { ok: true, count, can_open: canOpen?.supported === true };
      if (origin) reply.offer_save = await automaticSaveEnabled(origin);
      return reply;
    }
    case "popup_offer_save_safari": {
      let origin = null;
      try { origin = canonicalOrigin(request.origin); } catch { return { ok: false, error: "origin_mismatch" }; }
      if (typeof request.enabled !== "boolean") return { ok: false, error: "invalid_request" };
      const r = await setAutomaticSave(origin, request.enabled);
      if (r.ok) return { ok: true, offer_save: request.enabled };
      return { ok: false, error: r.error, message: r.error === "full" ? tr("safari_popup_offer_save_full") : tr("popup_auto_update_failed") };
    }
    case "popup_open_app_safari": {
      const r = await native({ action: "open_app" });
      return r?.opened === true ? { ok: true } : { ok: false, error: "unavailable", message: tr("safari_popup_open_failed") };
    }
  }
  return { ok: false, error: "unsupported" };
}

// ---- Panel relay (desktop parity: background.js panelRelay). content.js
// draws the save prompt in panel.html, the extension page it frames into the
// page (web-accessible in the Safari manifest), so the username field and the
// buttons are not in DOM the page can read or click by script. The frame asks
// for what to draw (ui_pull), reports its height (ui_size) and the user's
// clicks (ui_event); each goes, with the frame's browser-reported id and
// document, to the content script of the same tab (the frame's parent where
// webNavigation reports it). Only the content script that issued the random
// token answers, and only to the first frame that presented it. Nothing here
// reaches the native handler: Save itself is the content script's
// save_pending_browser with its own gesture nonce, as for the in-page panel.
// Pages cannot message the extension, and the sender must be our panel page.
const PANEL_PAGE = "panel.html";
const PANEL_TYPES = Object.freeze({ __proto__: null, ui_pull: "pull", ui_size: "size", ui_event: "event" });
const UI_TOKEN = /^[0-9a-f]{32}$/;
const UI_ID = /^[a-z0-9_-]{1,32}$/;
// Our own panel.html, framed inside a tab (never the top frame). Safari has
// no use_dynamic_url, so the whole extension URL (scheme, host, path) must match.
function fromPanel(sender) {
  if (!sender || sender.id !== api.runtime.id || !sender.tab || !Number.isInteger(sender.tab.id)) return false;
  if (!Number.isInteger(sender.frameId) || sender.frameId <= 0 || typeof sender.url !== "string" || typeof api.runtime.getURL !== "function") return false;
  try {
    const url = new URL(sender.url), own = new URL(api.runtime.getURL(PANEL_PAGE));
    return url.protocol === own.protocol && url.host === own.host && url.pathname === own.pathname;
  } catch { return false; }
}
// Only the fields the content script reads, each type-checked.
function panelMessage(request) {
  if (!UI_TOKEN.test(request.token ?? "")) return null;
  const op = PANEL_TYPES[request.type];
  const out = { command: "ui", op, token: request.token };
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
      // The save panel's edited username.
      if (!validText(request.value, 512, true)) return null;
      out.value = request.value;
    }
  }
  return out;
}
async function panelRelay(request, sender) {
  if (!fromPanel(sender)) return { ok: false, error: "untrusted_sender" };
  const message = panelMessage(request);
  if (!message) return { ok: false, error: "invalid_request" };
  message.frame = { id: sender.frameId, document: typeof sender.documentId === "string" ? sender.documentId : null };
  const tabId = sender.tab.id;
  let parent = null;
  try { parent = (await api.webNavigation?.getFrame?.({ tabId, frameId: sender.frameId }))?.parentFrameId; } catch { /* unknown: every frame of the tab is asked */ }
  try {
    const reply = Number.isInteger(parent) && parent >= 0
      ? await api.tabs.sendMessage(tabId, message, { frameId: parent })
      : await api.tabs.sendMessage(tabId, message);
    return reply && typeof reply === "object" ? reply : { ok: false };
  } catch { return { ok: false }; }
}

function native(message) {
  return new Promise(resolve => {
    let done = false;
    const finish = r => { if (!done) { done = true; clearTimeout(timer); resolve(r); } };
    const timer = setTimeout(() => finish(null), NATIVE_TIMEOUT_MS);
    Promise.resolve()
      .then(() => api.runtime.sendNativeMessage(NATIVE_APP_ID, message))
      .then(r => finish(r && typeof r === "object" ? r : null), () => finish(null));
  });
}
// The capture this document may act on: its own origin's, else (within
// HANDOFF_MS) one from the same tab on another origin of the same site.
async function findPending(tabId, origin, doc, now) {
  const ownKey = `${tabId}|${origin}`;
  const own = pending.get(ownKey);
  if (own) return boundTo(ownKey, own, doc, now) ? { key: ownKey, entry: own } : null;
  const prefix = `${tabId}|`;
  for (const [key, entry] of pending) {
    if (!key.startsWith(prefix) || entry.origin === origin || now - entry.created >= HANDOFF_MS || now < entry.created) continue;
    const r = await native({ action: "same_site", origin, other: entry.origin });
    if (r?.same === true && pending.get(key) === entry && boundTo(key, entry, doc, now)) return { key, entry };
  }
  return null;
}
async function classify(origin, username, password) {
  const r = await native({ action: "classify", origin, username, password });
  const status = r?.status;
  if (status === FILLED_STATUS) return FILLED_STATUS;
  return typeof status === "string" && PROMPT_STATUSES.has(status) ? status : "unavailable";
}
// Review R1 (desktop parity): the app classifies the save origin again and
// refuses a lookalike with "lookalike_site" plus the verdict until content.js
// has asked the guard question and resends with lookalike_confirmed. The
// native handler keeps String values only, so the flag goes as "true".
async function save(origin, username, password, status, confirmed = false) {
  if (status === "full") return { ok: false, error: "full", message: tr("bg_full_notice") };
  const message = { action: "save", origin, username, password, status };
  if (confirmed) message.lookalike_confirmed = "true";
  const r = await native(message);
  if (r?.stored === true) { if (badgeSupported()) void refreshBadge(true); return { ok: true, notice: tr("bg_saved_notice") }; }
  if (r?.error === "lookalike_site") {
    const verdict = appVerdict(r);
    if (verdict?.kind === "lookalike") return { ok: false, error: "lookalike_site", ...verdict };
  }
  const error = typeof r?.error === "string" && SAVE_ERRORS[r.error] ? r.error : "unavailable";
  return { ok: false, error, message: SAVE_ERRORS[error] };
}
// Phishing shield. The app compares the page origin with the saved origins
// (they never leave it: SafariSaveService.siteVerdict) and answers the
// verdict with its native classify. Only the verdict, the imitated host and
// an opaque pair id come back, checked here before content.js sees them.
const VERDICT_KINDS = new Set(["exact", "related", "lookalike", "unknown"]);
function appVerdict(r) {
  if (!r || typeof r !== "object" || !VERDICT_KINDS.has(r.site)) return null;
  const verdict = { kind: r.site, reason: typeof r.site_reason === "string" ? r.site_reason.slice(0, 32) : "" };
  verdict.matched = typeof r.site_matched === "string" && r.site_matched.length <= 253 && /^[\x21-\x7e]+$/.test(r.site_matched) ? r.site_matched : null;
  if (typeof r.site_pair === "string" && /^[0-9a-f]{32}$/.test(r.site_pair)) verdict.pair = r.site_pair;
  return verdict;
}
// When the app cannot answer (no site list yet, keys missing, an older app),
// Safari keeps the check that needs no saved origin: a host that mixes
// scripts is a lookalike (lookalike.js with the packaged psl-min.json, no
// network). Anything else stays unchecked.
let lookalikeRules = null;
async function localVerdict(origin) {
  if (typeof LGKLookalike === "undefined") return null;
  if (lookalikeRules === null) {
    lookalikeRules = fetch(api.runtime.getURL("psl-min.json")).then(r => r.json()).then(data => { LGKLookalike.setRules(data); return true; })
      .catch(() => { lookalikeRules = null; return false; });
  }
  try { return (await lookalikeRules) ? LGKLookalike.classify(origin, []) : null; } catch { return null; }
}
// Gesture proof, local to this page (no broker here): user_gesture plus a
// nonce minted by begin_gesture_browser for the same tab, origin, document
// and operation, used once within 30 s.
function gestureError(request, key, doc, now) {
  if (request.user_gesture !== true) return "user_gesture_required";
  const nonce = request.gesture_nonce;
  if (nonce === undefined || nonce === null) return "gesture_nonce_required";
  if (typeof nonce !== "string" || !/^[0-9a-f]{32}$/.test(nonce)) return "gesture_nonce_invalid";
  const g = gestures.get(nonce);
  gestures.delete(nonce);
  if (!g || g.key !== key || g.doc !== doc || g.operation_id !== request.operation_id || now >= g.expires) return "gesture_nonce_invalid";
  return null;
}

async function handle(request, sender) {
  if (!request || typeof request !== "object" || sender.id !== api.runtime.id) return { ok: false, error: "untrusted_sender" };
  if (!sender.tab || !Number.isInteger(sender.tab.id) || typeof sender.url !== "string") return { ok: false, error: "untrusted_sender" };
  const origin = senderOrigin(sender.url);
  if (!origin) return { ok: false, error: "origin_mismatch" };
  let claimed = null;
  try { claimed = canonicalOrigin(request.origin); } catch { /* not an origin */ }
  if (origin !== claimed) return { ok: false, error: "origin_mismatch" };
  // An opaque-origin document (sandboxed) has the site's URL but origin "null".
  if (typeof sender.origin === "string" && senderOrigin(sender.origin) !== origin) return { ok: false, error: "origin_mismatch" };
  if (!validText(request.operation_id, 128)) return { ok: false, error: "invalid_request" };
  if (!HANDLED.has(request.type)) return { ok: false, error: "unsupported" };
  if (!(await frameChainOk(sender, origin))) return { ok: false, error: "origin_mismatch" };

  const tabId = sender.tab.id;
  const key = `${tabId}|${origin}`;
  const doc = documentOf(request, sender);
  const now = Date.now();
  sweep(now);
  switch (request.type) {
    case "status":
      return { ok: true, version: api.runtime.getManifest().version, features: { fill: false } };
    case "classify_site_browser": {
      const verdict = appVerdict(await native({ action: "classify", origin }));
      if (verdict) return { ok: true, ...verdict };
      const local = await localVerdict(origin);
      if (local?.kind === "lookalike") return { ok: true, kind: "lookalike", reason: local.reason, matched: null, local: true };
      return { ok: true, unchecked: true };
    }
    case "begin_gesture_browser": {
      if (request.user_gesture !== true) return { ok: false, error: "user_gesture_required" };
      if (gestures.size >= MAX_GESTURES) gestures.delete(gestures.keys().next().value);
      const nonce = randomHex();
      gestures.set(nonce, { key, doc, operation_id: request.operation_id, expires: now + GESTURE_TTL_MS });
      return { ok: true, gesture_nonce: nonce, gesture_expires_in: GESTURE_TTL_MS / 1000 };
    }
    case "capture_browser":
    case "check_browser":
    case "save_browser": {
      if (!validText(request.username, 512, true) || !validText(request.password, 4096)) return { ok: false, error: "invalid_credential" };
      const { username, password } = request;
      if (request.type === "save_browser") {
        const refused = gestureError(request, key, doc, now);
        if (refused) return { ok: false, error: refused };
        const status = await classify(origin, username, password);
        if (status === "unavailable") return { ok: false, error: "unavailable", message: SAVE_ERRORS.unavailable };
        // The user pressed Save: a just-filled login is one the vault holds,
        // and the app's save ignores the fill marker, so it is saved as an
        // update like "exists" (never refused as "unavailable").
        return save(origin, username, password, status === FILLED_STATUS ? "exists" : status, request.lookalike_confirmed === true);
      }
      // A password-only step (a change-password form) does not say which login
      // changed, and Safari cannot list the site's saved logins to ask: it is
      // never kept, so it can never be saved as a new, nameless login (desktop
      // parity: there it may only update a login the user picks).
      if (request.type === "capture_browser" && !username) return { ok: true, stored: false, status: "username_required" };
      if (!probeAllowed(origin, now)) return { ok: false, error: "rate_limited", message: tr("bg_rate_limited") };
      const status = await classify(origin, username, password);
      if (request.type === "check_browser") {
        // "filled" reads exactly like "unavailable" here: the page must not tell them apart.
        const reply = { ok: true, status: status === FILLED_STATUS ? "unavailable" : status, match: false, prompt: PROMPT_STATUSES.has(status) };
        if (status === "full") reply.notice = tr("bg_full_notice");
        return reply;
      }
      // No prompt for this sign-in ("filled" or "unavailable"): an older
      // capture of this tab is dropped too, so the landing page never offers
      // a password the user has since replaced (for "filled", one AutoFill
      // replaced). Both answers drop it alike, so the page cannot tell them apart.
      if (!PROMPT_STATUSES.has(status)) { dropTab(tabId); return { ok: true, stored: false }; }
      dropTab(tabId);
      const token = randomHex();
      pending.set(key, { token, origin, username, password, status, created: Date.now(), doc });
      return { ok: true, stored: true, pending_token: token };
    }
    case "pending_browser": {
      const found = await findPending(tabId, origin, doc, now);
      if (!found) return { ok: true, pending: false };
      const { entry } = found;
      const reply = { ok: true, pending: true, pending_token: entry.token, status: entry.status, age_ms: Math.max(0, now - entry.created) };
      // Another origin of the same site learns which origin the login is for,
      // never its username: nothing proves the browser came here from there.
      if (entry.origin !== origin) { reply.origin = entry.origin; reply.handoff = true; }
      else reply.username = entry.username;
      if (entry.status === "full") reply.notice = tr("bg_full_notice");
      return reply;
    }
    case "save_pending_browser": {
      if (!validText(request.pending_token, 128)) return { ok: false, error: "invalid_pending_token" };
      // The username the user edited in the panel frame (desktop parity),
      // sent with the Save click; absent when it was left as captured.
      if (request.username !== undefined && !validText(request.username, 512)) return { ok: false, error: "invalid_credential" };
      const refused = gestureError(request, key, doc, now);
      if (refused) return { ok: false, error: refused };
      const found = await findPending(tabId, origin, doc, now);
      if (!found || found.entry.token !== request.pending_token || pending.get(found.key) !== found.entry) {
        return { ok: false, error: "not_found", message: tr("bg_not_waiting") };
      }
      // The panel offers no username field on a landing page of another
      // origin (a handoff): the login is for the page it was typed on.
      if (request.username !== undefined && found.entry.origin !== origin) return { ok: false, error: "invalid_credential" };
      // One attempt per capture: the password leaves memory whatever the outcome,
      // except a lookalike refusal, which puts it back for the one retry the
      // guard question sends (lookalike_confirmed). It is saved for the site it
      // was typed on, not the page it landed on.
      const { entry } = found;
      pending.delete(found.key);
      // Never a new login from a capture without a username (none is kept, see capture_browser).
      if (!entry.username) return { ok: false, error: "entry_required" };
      // The username edited in the frame goes straight to the app's save,
      // which classifies it itself (full, new or exists) and answers full,
      // unavailable or lookalike_site as for the captured one: no extra
      // classify (no probe) here.
      const username = request.username !== undefined ? request.username : entry.username;
      const result = await save(entry.origin, username, entry.password, entry.status, request.lookalike_confirmed === true);
      if (result.error === "lookalike_site" && !request.lookalike_confirmed && !pending.has(found.key)) pending.set(found.key, entry);
      return result;
    }
    case "discard_pending_browser": {
      const found = await findPending(tabId, origin, doc, now);
      if (found && found.entry.token === request.pending_token) pending.delete(found.key);
      return { ok: true };
    }
    case "clear_pending_browser":
      pending.delete(key);
      return { ok: true };
    case "never_site_browser":
      // "Never on this site" from the save prompt; the toolbar popup's switch turns it back on.
      return (await setAutomaticSave(origin, false)).ok ? { ok: true } : { ok: false, error: "unavailable" };
    case "agent_status_browser": {
      // Whether the field icon may offer an agent's sign-in at all; nothing about any grant.
      if (now - agentStatus.at >= AGENT_STATUS_TTL_MS || now < agentStatus.at) {
        const r = await native({ action: "agent_status" });
        agentStatus = { at: Date.now(), agent: r?.ok === true && r.agent === true };
      }
      return { ok: true, agent: agentStatus.agent };
    }
    case "fill_grant_browser": {
      if (!doc) return { ok: false, error: "not_found" };
      // The app takes (and uses up) a grant armed for this page's exact host.
      const r = await native({ action: "agent_offer", url: sender.url });
      if (r?.error === "agent_passkey") {
        const message = typeof r.message === "string" && r.message.length <= 300 ? r.message : "";
        return { ok: false, error: "agent_passkey", ...(message ? { message } : {}) };
      }
      if (r?.ok !== true || typeof r.grant !== "string" || !validText(r.grant, 128) || r.origin !== origin || !Array.isArray(r.choices)) {
        return { ok: false, error: "not_found" };
      }
      const choices = r.choices.filter(c => c && typeof c === "object" && validText(c.entry_id, 128) && validText(c.username, 512, true)
        && validText(c.label, 512, true) && c.require_master_password !== true).slice(0, 32)
        .map(c => ({ entry_id: c.entry_id, username: c.username, label: c.label, favorite: c.favorite === true,
          match: typeof c.match === "string" ? c.match.slice(0, 32) : "exact_origin" }));
      if (!choices.length) return { ok: false, error: "not_found" };
      if (offers.size >= MAX_OFFERS) offers.delete(offers.keys().next().value);
      const token = randomHex();
      offers.set(token, { key, doc, native: r.grant, entries: new Set(choices.map(c => c.entry_id)), expires: now + OFFER_TTL_MS, released: null });
      return { ok: true, grant: token, choices };
    }
    case "get_browser": {
      const found = offerFor(request, key, doc, now);
      if (!found || found.offer.released !== null) return { ok: false, error: "unsupported" };
      // The second click: the picker row the user chose (gesture nonce from begin_gesture_browser).
      const refused = gestureError(request, key, doc, now);
      if (refused) return { ok: false, error: refused };
      const { token, offer } = found;
      if (!validText(request.entry_id, 128) || !offer.entries.has(request.entry_id)) return { ok: false, error: "not_found" };
      offer.released = request.entry_id;
      const r = await native({ action: "agent_release", url: sender.url, grant: offer.native, entry_id: request.entry_id });
      if (r?.ok !== true || !validText(r.username, 512, true) || !validText(r.password, 4096, true)) {
        offers.delete(token);
        return { ok: false, error: "not_found" };
      }
      const credential = request.username_only === true ? { username: r.username } : { username: r.username, password: r.password };
      return { ok: true, credential };
    }
    case "validate_browser": {
      // Once, right before the fill, for the login just released.
      const found = offerFor(request, key, doc, now);
      if (!found || found.offer.released === null) return { ok: false, error: "unsupported" };
      offers.delete(found.token);
      return found.offer.released === request.entry_id ? { ok: true } : { ok: false, error: "not_found" };
    }
    case "cancel_browser": {
      const found = offerFor(request, key, doc, now);
      if (!found) return { ok: false, error: "unsupported" };
      offers.delete(found.token);
      return { ok: true };
    }
  }
  return { ok: false, error: "unsupported" };
}

api.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const message = request && typeof request === "object";
  const answer = message && fromPopup(sender) ? handlePopup(request)
    : message && PANEL_TYPES[request.type] ? panelRelay(request, sender) : handle(request, sender);
  answer.then(sendResponse, () => sendResponse({ ok: false, error: "unavailable" }));
  return true;
});
// The badge follows the inbox: at start, after a save (above), when the popup
// opens, and (at most every 30 s) when the user switches tabs, since the app
// empties the inbox at its unlock without telling the extension.
if (badgeSupported()) {
  api.runtime.onStartup?.addListener?.(() => { void refreshBadge(true); });
  api.runtime.onInstalled?.addListener?.(() => { void refreshBadge(true); });
  api.tabs?.onActivated?.addListener?.(() => { void refreshBadge(); });
}
// A finished load in a tab with a waiting capture asks its content script to
// re-check (tabs.onUpdated; webNavigation is used for frame checks only).
api.tabs?.onUpdated?.addListener((tabId, changeInfo) => {
  if (changeInfo?.status !== "complete") return;
  const prefix = `${tabId}|`;
  if (![...pending.keys()].some(key => key.startsWith(prefix))) return;
  try {
    const sent = api.tabs.sendMessage(tabId, { command: "check_pending_save" });
    if (sent && typeof sent.catch === "function") sent.catch(() => {});
  } catch { /* tab already gone */ }
});
api.tabs?.onRemoved?.addListener(tabId => dropTab(tabId));
