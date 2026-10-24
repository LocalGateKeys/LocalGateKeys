"use strict";
// Chrome runs this file as a classic service worker: pull in the namespace
// shim. Firefox (build-firefox-manifest.cjs) lists api.js before this file in
// background.scripts, so `api` already exists there and importScripts is absent.
if (typeof api === "undefined" && typeof importScripts === "function") importScripts("api.js");
const HOST_NAME = "com.localgatekeys.app";
const PROTOCOL = 2;
const IDENTITY_FILL_PROTOCOL = 1;
const CARD_FILL_PROTOCOL = 1;
const PASSKEY_PROTOCOL = 1;
const PASSKEY_TYPES = new Set(["passkey_create_browser","passkey_get_browser"]);
// Serialized WebAuthn options from webauthn-page.js; larger requests go to the browser.
const MAX_PASSKEY_OPTIONS = 65536;
const CARD_FIELDS = new Set(["cc-name","cc-number","cc-exp","cc-exp-month","cc-exp-year","cc-csc","cc-type"]);
// Actions that may carry the page URL for multi-URL (starts_with) matching.
const URL_ACTIONS = new Set(["begin_browser","get_browser"]);
const EXTENSION_VERSION = api.runtime.getManifest().version;
const MAX_FRAME_DEPTH = 32;
// content.js: crypto.randomUUID() without dashes, once per document.
const DOCUMENT_KEY = /^[0-9a-f]{32}$/;

function canonicalOrigin(value) {
  const u = new URL(value);
  if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) throw new Error("Expected an origin");
  const local = u.hostname === "localhost" || u.hostname.endsWith(".localhost") || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new Error("Use HTTPS (or local test pages)");
  return u.origin;
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
  agent_offline: "The older native host could not reach the app. If LocalGateKeys is already open, update the desktop app, repair the bridge, and restart it.",
  agent_state_missing: "No running connection was found. Finish choosing a profile in LocalGateKeys. If the main window is already open, restart the app from the same repository as the bridge.",
  agent_state_invalid: "The saved bridge connection is invalid or outdated. Exit LocalGateKeys fully, including the tray, and restart the repository copy.",
  agent_access_denied: "Windows denied access to the bridge. Run the browser and LocalGateKeys as the same Windows user without Administrator mode, then repair the current-user bridge.",
  agent_unavailable: "The app connection is not accepting requests. Exit LocalGateKeys fully (including the tray), then restart it from the repository used to repair the bridge.",
  agent_busy: "The bridge is busy. Finish any open LocalGateKeys dialog and try again.",
  agent_connection_lost: "The local bridge disconnected before replying. Repair the bridge if this repeats. No automatic retry was made.",
  agent_connection_changed: "The connection points to a different app instance. Restart LocalGateKeys from the repository used to repair the bridge.",
  bridge_dependencies_missing: "The native host is missing required Python packages. Refresh the repository environment, then run scripts/repair_browser_bridge.ps1.",
  bridge_protocol_error: "The local bridge returned an invalid response. Update all bridge files together and restart LocalGateKeys.",
  bridge_internal_error: "The native bridge encountered an error. Run scripts/test_browser_bridge.ps1 and share its sanitized report.",
  caller_not_browser: "LocalGateKeys only accepts requests from a native host started by a signed browser. Restart the browser; if this repeats, repair the bridge from Connections in LocalGateKeys.",
  rate_limited: "Too many password checks from this site in a short time. Wait a minute and try again.",
  unauthorized: "The bridge token no longer matches the app. Exit LocalGateKeys fully, restart the repository copy, and reload this page.",
  version_mismatch: "Update/reload the extension and restart LocalGateKeys. Their versions do not match.",
  client_not_allowed: "LocalGateKeys rejected the native-host identity. Exit the app, run scripts/repair_browser_bridge.ps1 from the repository, then restart LocalGateKeys.",
  session_changed: "The vault locked, the profile changed, or this request expired. Click the icon again.",
  integration_disabled: "Browser integration is paused in LocalGateKeys.",
  not_found: "No permitted saved login for this exact website. Save a login or check its fill policy.",
  destination_changed: "The page or active tab changed. Click the icon again on the intended login form.",
  busy: "Finish the open LocalGateKeys prompt first.",
  identity_not_found: "No identity profile is available in this profile.",
  invalid_identity_fields: "Choose only the reviewed contact or address fields.",
  user_cancelled: "Identity fill was cancelled before any field was released.",
  user_gesture_required: "Start this action from the extension or an in-page LocalGateKeys button.",
  gesture_nonce_invalid: "The click expired or belongs to another page. Click again.",
  gesture_nonce_required: "Update the browser extension: this action needs a fresh gesture nonce.",
  origin_mismatch: "The page origin changed. Start identity fill again on the intended page.",
  invalid_request: "The identity request was rejected because its page context changed.",
  invalid_approval: "The identity approval is invalid or expired. Start again.",
  card_not_found: "No payment card is saved in this profile.",
  invalid_card_fields: "Choose only the reviewed card fields.",
  totp_not_found: "No saved login for this exact site has a 2FA setup key.",
  unsupported_request: "This extension action is not supported by the current bridge.",
};
function itemLimitMessage(limit) {
  const count = Number.isInteger(limit) && limit > 0 ? limit : 4;
  return `Your free LocalGateKeys holds ${count} items. Upgrade to Pro for unlimited.`;
}
function hostError(message) {
  if (/not found/i.test(message)) return "Native host is not registered. Repair the browser connection from LocalGateKeys.";
  if (/forbidden/i.test(message)) return "Extension ID is not allowed by the native-host registration. Repair the bridge.";
  if (/exited/i.test(message)) return "The native host stopped unexpectedly. Open Connections in LocalGateKeys for diagnostics.";
  return "Browser connection failed. Open Connections in LocalGateKeys.";
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
    const timer = setTimeout(() => finish({ok:false,error:"timeout",message:"The LocalGateKeys bridge did not respond. Close any stale desktop prompt and try again."}), timeoutMs);
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
// The sender frame must be the top frame or an iframe whose whole ancestor
// chain (browser-reported, never page-supplied) shares the expected origin.
async function documentStillCurrent(sender, expectedOrigin, activeRequired) {
  const tabId = sender.tab.id;
  const frame = await frameInfo(tabId, sender.frameId);
  if (!frame || frame.errorOccurred) return false;
  // Chromium reports the lifecycle; Firefox does not. Only an explicit non-active state rejects.
  if (frame.documentLifecycle !== undefined && frame.documentLifecycle !== "active") return false;
  // Chromium pins the exact document through documentId. Firefox has no
  // documentId on either side; it falls back to the tab + frame-URL origin
  // check below. A documentId present on only one side is a mismatch.
  if (sender.documentId !== undefined || frame.documentId !== undefined) {
    if (!sender.documentId || frame.documentId !== sender.documentId) return false;
  }

  // SPAs such as FACEIT may use history.pushState/replaceState while keeping
  // the same document and login form alive. Path/query/hash changes are not a
  // destination change. The security boundary is the exact origin plus the
  // browser-provided documentId (or, on Firefox, the tab and frame origin).
  if (frameOrigin(frame) !== expectedOrigin) return false;

  let current = frame, frameId = sender.frameId;
  for (let depth = 0; frameId !== 0; depth++) {
    if (depth >= MAX_FRAME_DEPTH) return false;
    const parentId = current.parentFrameId;
    if (!Number.isInteger(parentId) || parentId < 0) return false;
    const parent = await frameInfo(tabId, parentId);
    if (!parent || parent.errorOccurred || frameOrigin(parent) !== expectedOrigin) return false;
    current = parent; frameId = parentId;
  }

  const tab = await api.tabs.get(tabId);
  return !tab.discarded && (!activeRequired || tab.active);
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

api.runtime.onMessage.addListener((request, sender, sendResponse) => {
  (async () => {
    if (!request || typeof request !== "object" || sender.id !== api.runtime.id) return {ok:false,error:"untrusted_sender"};
    // Only the packaged extension popup can request diagnostics without a tab.
    if (!sender.tab && sender.url === api.runtime.getURL("popup.html") && request.type === "diagnostics") {
      const r = await nativeRequest({action:"ping"});
      return {...r,extension_version:EXTENSION_VERSION};
    }
    // Any frame may ask; documentStillCurrent verifies it against the
    // browser's frame tree (same-origin ancestry up to the top frame).
    if (!sender.tab || !Number.isInteger(sender.tab.id) || !Number.isInteger(sender.frameId) || sender.frameId < 0 || typeof sender.url !== "string") return {ok:false,error:"untrusted_sender"};
    const origin = canonicalOrigin(new URL(sender.url).origin);
    if (origin !== canonicalOrigin(request.origin)) return {ok:false,error:"origin_mismatch"};
    if (!validText(request.operation_id, 128)) return {ok:false,error:"invalid_request"};
    const allowed = new Set(["ping","begin_browser","begin_gesture_browser","get_browser","validate_browser","submit_browser","cancel_browser","check_browser","save_browser","capture_browser","pending_browser","save_pending_browser","discard_pending_browser","clear_pending_browser","begin_identity_browser","approve_identity_browser","release_identity_browser","cancel_identity_browser","begin_card_browser","approve_card_browser","release_card_browser","cancel_card_browser","begin_totp_browser","get_totp_browser","passkey_create_browser","passkey_get_browser"]);
    if (!allowed.has(request.type)) return {ok:false,error:"unsupported_request"};
    const activeRequired = !["ping","cancel_browser","check_browser","capture_browser","pending_browser","discard_pending_browser","clear_pending_browser"].includes(request.type);
    if (!(await documentStillCurrent(sender, origin, activeRequired))) return {ok:false,error:"destination_changed",message:readableErrors.destination_changed};
    // Browser-derived document identity, never caller-supplied tab/frame IDs.
    // Firefox has no documentId; the frame id plus the random per-document key
    // content.js draws when it loads stand in, so that two frames of one tab,
    // or two documents loaded one after the other in one frame, never share a
    // context. Pages cannot message the extension, so the key comes from our
    // own content script.
    const documentKey = sender.documentId ?? (typeof request.document_key === "string" && DOCUMENT_KEY.test(request.document_key)
      ? `frame:${sender.frameId}:${request.document_key}` : `frame:${sender.frameId}`);
    const context = JSON.stringify([sender.tab.id,documentKey,origin,request.operation_id]);
    const payload = {action:request.type,origin,context};
    if (URL_ACTIONS.has(request.type) && request.url !== undefined && request.url !== null) {
      const url = pageUrlFor(request.url, origin);
      if (url !== undefined) payload.url = url;
    }
    if (PASSKEY_TYPES.has(request.type)) {
      // WebAuthn options are page data. The broker parses and bounds every
      // field; here only the protocol pin and the overall size are checked.
      // "fallback" makes webauthn-page.js use the browser's own authenticator.
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
    payload.username_only=request.username_only===true;
    if (["save_browser","save_pending_browser","get_browser","capture_browser"].includes(request.type)) {
      const icon = await siteIcon(sender.url);
      if (icon) payload.site_icon = icon;
    }
    const response = await nativeRequest(payload);
    // Drop late replies if navigation/tab switching changed the destination.
    if (!(await documentStillCurrent(sender,origin,activeRequired))) return {ok:false,error:"destination_changed",message:readableErrors.destination_changed};
    // Login and 2FA pickers list accounts for this page's own origin: draw its logo.
    if (response?.ok && Array.isArray(response.choices) && ["begin_browser","begin_totp_browser"].includes(request.type)) {
      const logo = await siteLogo(origin);
      if (logo) response.site_logo = logo;
    }
    return response;
  })().then(sendResponse).catch(() => sendResponse({ok:false,error:"destination_changed",message:readableErrors.destination_changed}));
  return true;
});
