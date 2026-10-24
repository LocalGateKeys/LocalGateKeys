"use strict";
// Safari on iPhone: non-persistent background page, loaded after api.js
// (see build-safari-extension.cjs). It does in the extension what the desktop
// broker does in process memory for the save prompt, and nothing else: the
// extension cannot fill, read the vault, or see the master password.
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
const RATE_LIMITED = "Too many login checks from this site. Wait a minute and try again.";
const DOCUMENT_KEY = /^[0-9a-f]{32}$/;
const MAX_FRAME_DEPTH = 32;
const FULL_NOTICE = "Your free vault is full. Upgrade in LocalGateKeys to save more.";
const SAVED_NOTICE = "Saved. It will appear in LocalGateKeys next time you open it.";
const SAVE_ERRORS = {
  full: FULL_NOTICE,
  inbox_full: "Too many logins are waiting. Open LocalGateKeys to import them, then sign in again to save it.",
  invalid: "This login could not be saved.",
  unavailable: "Open LocalGateKeys and unlock it once to turn on saving from Safari, then sign in again to save it.",
};
// The app's classify answers only "new", "exists", "full" or "unavailable":
// it never tells the extension (or the page) whether a password matches the
// saved one. Passwords are compared inside the app at import, after the user
// confirms there. "exists" prompts a neutral save-or-update; "unavailable"
// (and anything else) means no prompt.
const PROMPT_STATUSES = new Set(["new", "exists", "full"]);
const HANDLED = new Set(["status", "capture_browser", "pending_browser", "save_pending_browser", "discard_pending_browser",
  "clear_pending_browser", "check_browser", "save_browser", "begin_gesture_browser"]);

// `${tabId}|${origin}` -> {token, origin, username, password, status, created, doc}; at most one per tab.
const pending = new Map();
// gesture nonce -> {key, doc, operation_id, expires}; single use.
const gestures = new Map();
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
  return typeof status === "string" && PROMPT_STATUSES.has(status) ? status : "unavailable";
}
async function save(origin, username, password, status) {
  if (status === "full") return { ok: false, error: "full", message: FULL_NOTICE };
  const r = await native({ action: "save", origin, username, password, status });
  if (r?.stored === true) return { ok: true, notice: SAVED_NOTICE };
  const error = typeof r?.error === "string" && SAVE_ERRORS[r.error] ? r.error : "unavailable";
  return { ok: false, error, message: SAVE_ERRORS[error] };
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
        return save(origin, username, password, status);
      }
      if (!probeAllowed(origin, now)) return { ok: false, error: "rate_limited", message: RATE_LIMITED };
      const status = await classify(origin, username, password);
      if (request.type === "check_browser") {
        const reply = { ok: true, status, match: false, prompt: PROMPT_STATUSES.has(status) };
        if (status === "full") reply.notice = FULL_NOTICE;
        return reply;
      }
      if (!PROMPT_STATUSES.has(status)) return { ok: true, stored: false };
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
      if (entry.status === "full") reply.notice = FULL_NOTICE;
      return reply;
    }
    case "save_pending_browser": {
      if (!validText(request.pending_token, 128)) return { ok: false, error: "invalid_pending_token" };
      const refused = gestureError(request, key, doc, now);
      if (refused) return { ok: false, error: refused };
      const found = await findPending(tabId, origin, doc, now);
      if (!found || found.entry.token !== request.pending_token || pending.get(found.key) !== found.entry) {
        return { ok: false, error: "not_found", message: "This login is no longer waiting to be saved." };
      }
      // One attempt per capture: the password leaves memory whatever the outcome.
      // It is saved for the site it was typed on, not the page it landed on.
      const { entry } = found;
      pending.delete(found.key);
      return save(entry.origin, entry.username, entry.password, entry.status);
    }
    case "discard_pending_browser": {
      const found = await findPending(tabId, origin, doc, now);
      if (found && found.entry.token === request.pending_token) pending.delete(found.key);
      return { ok: true };
    }
    case "clear_pending_browser":
      pending.delete(key);
      return { ok: true };
  }
  return { ok: false, error: "unsupported" };
}

api.runtime.onMessage.addListener((request, sender, sendResponse) => {
  handle(request, sender).then(sendResponse, () => sendResponse({ ok: false, error: "unavailable" }));
  return true;
});
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
