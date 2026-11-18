"use strict";
// Safari toolbar popup (popup-safari.html), loaded after api.js. It shows the
// tab's host, how to fill with Safari AutoFill, the per-site save switch, how
// many logins wait in the app's Safari inbox, and on the Mac an "Open
// LocalGateKeys" button. It never lists, fills or receives a login: every
// request goes to background-safari.js, which answers with a count and a
// boolean only.

const $ = id => document.getElementById(id);
// Right after Safari starts cold the background page can take many seconds to
// answer; past this the popup shows the failure wording instead of "Loading…".
const STATE_TIMEOUT_MS = 30000;

function send(type, extra = {}) {
  return Promise.resolve()
    .then(() => api.runtime.sendMessage({ type, ...extra }))
    .then(r => (r && typeof r === "object" ? r : { ok: false }), () => ({ ok: false }));
}

function localize() {
  for (const el of document.querySelectorAll("[data-i18n]")) {
    const text = tr(el.dataset.i18n);
    if (text && text !== el.dataset.i18n) el.textContent = text;
  }
  try { document.documentElement.lang = api.i18n.getUILanguage(); } catch { /* keep the default */ }
}

// The tab's site as the content script sees it (location.origin), only for
// pages the extension saves for: https, or http on localhost.
function siteOf(url) {
  try {
    const u = new URL(url);
    const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
    if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) return { host: u.protocol.startsWith("http") ? u.hostname : "", origin: null };
    return { host: u.hostname, origin: u.origin };
  } catch { return { host: "", origin: null }; }
}

async function currentTab() {
  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    return tab || null;
  } catch { return null; }
}

function showError(message) {
  const el = $("error");
  el.textContent = message || "";
  el.hidden = !message;
}

function showCount(count) {
  const n = Number.isInteger(count) && count > 0 ? count : 0;
  $("waiting").textContent = n === 1 ? tr("safari_popup_waiting_one") : tr("safari_popup_waiting_many", n);
  $("waiting-row").hidden = n === 0;
}

// The background's reply, or { ok: false } after STATE_TIMEOUT_MS.
function sendWithin(type, extra, ms) {
  return new Promise(resolve => {
    const timer = setTimeout(() => resolve({ ok: false, error: "timeout" }), ms);
    send(type, extra).then(r => { clearTimeout(timer); resolve(r); });
  });
}

async function init() {
  localize();
  // Sheet layout until the native handler says it can open the app (the Mac's
  // does): the slow cold start is the iPhone's, so it never waits as a Mac popup.
  document.documentElement.classList.add("ios");
  const tab = await currentTab();
  // Safari gives tabs.query a url only for sites the user allowed the extension on (no activeTab here): a tab
  // without one is a site still to allow, not an empty tab.
  const hasUrl = !!tab && typeof tab.url === "string" && tab.url !== "";
  const site = siteOf(hasUrl ? tab.url : "");
  const notAllowed = !!tab && !hasUrl;
  $("host").textContent = site.host || (notAllowed ? tr("safari_popup_not_allowed") : tr("safari_popup_no_site"));
  // The not-allowed hint is a sentence: it wraps instead of being cut like a host name.
  if (notAllowed) $("host").classList.add("note");

  // The header and the fill card show at once; "Loading…" holds the place of the switch and count rows.
  const state = await sendWithin("popup_state_safari", site.origin ? { origin: site.origin } : {}, STATE_TIMEOUT_MS);
  $("loading").hidden = true;
  if (!state.ok) showError(tr("popup_auto_read_failed"));
  // can_open comes from the native handler: only the Mac's can open the app. Without it (iPhone, iPad) the
  // popup is a sheet and the button stays hidden.
  const canOpen = state.ok === true && state.can_open === true;
  if (canOpen) document.documentElement.classList.remove("ios");
  showCount(state.ok ? state.count : 0);

  const toggle = $("offer-save");
  if (site.origin && state.ok && typeof state.offer_save === "boolean") {
    toggle.checked = state.offer_save;
    $("offer-row").hidden = false;
    toggle.addEventListener("change", async () => {
      const want = toggle.checked;
      toggle.disabled = true;
      showError("");
      const r = await send("popup_offer_save_safari", { origin: site.origin, enabled: want });
      if (!r.ok) {
        toggle.checked = !want;
        showError(typeof r.message === "string" ? r.message : tr("popup_auto_update_failed"));
      }
      toggle.disabled = false;
    });
  }

  // Only the Mac's native handler can open the app (NSWorkspace) and says so
  // (open_app_supported); Safari on iPhone has no supported way to, so the
  // button is never shown there.
  if (canOpen) {
    const open = $("open-app");
    open.hidden = false;
    open.addEventListener("click", async () => {
      open.disabled = true;
      showError("");
      const r = await send("popup_open_app_safari");
      if (r.ok) { window.close(); return; }
      open.disabled = false;
      showError(typeof r.message === "string" ? r.message : tr("safari_popup_open_failed"));
    });
  }
}

void init();
