"use strict";

const statusNode = document.getElementById("status");
const siteNode = document.getElementById("site");
const siteStateNode = document.getElementById("site-state");
const chipNode = document.getElementById("chip");
const fillNode = document.getElementById("fill");
const loginsReadyNode = document.getElementById("logins-ready");
const loginsGateNode = document.getElementById("logins-gate");
const gateTextNode = document.getElementById("gate-text");
const gateActionNode = document.getElementById("gate-action");
const generateNode = document.getElementById("generate");
const generatorNode = document.getElementById("generator");
const automaticNode = document.getElementById("automatic");
const automaticHintNode = document.getElementById("automatic-hint");
// Sites where the save prompt is turned off. Every other site asks by default.
const AUTOMATIC_KEY = "automatic_save_blocked_origins";
// "generate" only opens the generator panel (copy works without the app), so it
// is not gated; the panel's "Fill on page" goes through sendCommand like the rest.
const FIELD_ACTION_IDS = ["fill", "identity", "card", "save"];
const PAGE_ACTION_IDS = [...FIELD_ACTION_IDS, "automatic"];
const COMMAND_LABELS = {
  fill_current: tr("popup_fill_login"),
  fill_identity: tr("popup_fill_identity"),
  fill_card: tr("popup_fill_card_label"),
  save_current: tr("popup_save_login"),
  generate_new: tr("popup_generate_password"),
};
const DIAGNOSTIC_ERRORS = {
  agent_offline: tr("popup_diag_agent_offline"),
  agent_state_missing: tr("popup_diag_state_missing"),
  agent_state_invalid: tr("popup_diag_state_invalid"),
  agent_unavailable: tr("popup_diag_unavailable"),
  agent_connection_lost: tr("popup_diag_connection_lost"),
  version_mismatch: tr("popup_diag_version_mismatch"),
  integration_disabled: tr("popup_integration_disabled"),
  native_host_error: tr("popup_diag_native_host"),
  timeout: tr("popup_diag_timeout"),
};
const COMMAND_ERRORS = {
  not_found: tr("popup_cmd_not_found"),
  session_changed: tr("popup_cmd_session_changed"),
  integration_disabled: tr("popup_integration_disabled"),
  destination_changed: tr("popup_cmd_destination_changed"),
  busy: tr("popup_cmd_busy"),
  agent_offline: tr("popup_cmd_offline"),
  identity_not_found: tr("popup_cmd_identity_not_found"),
  invalid_identity_fields: tr("popup_cmd_invalid_identity"),
  user_cancelled: tr("popup_cmd_cancelled"),
  card_not_found: tr("popup_cmd_card_not_found"),
  card_form_not_found: tr("popup_cmd_card_form_not_found"),
  invalid_card_fields: tr("popup_cmd_invalid_card"),
  origin_mismatch: tr("popup_cmd_origin_mismatch"),
  version_mismatch: tr("popup_cmd_version_mismatch"),
  gesture_nonce_invalid: tr("popup_cmd_nonce_invalid"),
  gesture_nonce_required: tr("popup_cmd_nonce_required"),
};

let currentTab = null;
let connectionRequest = null;
let diagnosticsState = "checking";
let commandInFlight = false;
let lastDiagnostics = null;

function setStatus(message, kind = "info") {
  statusNode.textContent = message || "";
  statusNode.dataset.kind = kind;
  statusNode.hidden = !message;
}

// Header chip: one word for the state, the longer description as its tooltip.
function setConnectionStatus(state, title, description) {
  chipNode.dataset.state = state;
  chipNode.textContent = title;
  chipNode.title = description;
  updateLoginsGate();
}

// "Logins for this site" shows the Fill row when the app can answer, and one
// explanation with a single clear action otherwise.
function updateLoginsGate() {
  let text = "";
  let action = null;
  if (!currentTab && diagnosticsState !== "checking") {
    text = tr("popup_page_unavailable_hint");
  } else if (diagnosticsState === "locked") {
    text = tr("popup_unlock_explain");
    action = "unlock";
  } else if (diagnosticsState === "offline") {
    text = diagnosticError(lastDiagnostics);
    action = "refresh";
  } else if (diagnosticsState === "setup") {
    text = tr("popup_setup_desc");
    action = "refresh";
  }
  const gated = Boolean(text);
  loginsReadyNode.hidden = gated;
  loginsGateNode.hidden = !gated;
  gateTextNode.textContent = text;
  gateActionNode.hidden = !action;
  gateActionNode.dataset.action = action || "";
  if (action) gateActionNode.textContent = action === "unlock" ? tr("popup_unlock_button") : tr("popup_check_again");
}

function setPageActionsEnabled(enabled) {
  for (const id of PAGE_ACTION_IDS) document.getElementById(id).disabled = !enabled;
}

function setFieldActionsEnabled(enabled) {
  const value = enabled === true && Boolean(currentTab) && !commandInFlight;
  for (const id of FIELD_ACTION_IDS) document.getElementById(id).disabled = !value;
}

function setAutomaticAvailable(enabled) {
  automaticNode.disabled = enabled !== true || !currentTab;
}

function updateFieldActionAvailability() {
  setFieldActionsEnabled(diagnosticsState === "connected" || diagnosticsState === "locked");
  gateActionNode.disabled = commandInFlight || Boolean(connectionRequest);
}

function fieldActionsReady() {
  return Boolean(currentTab && (diagnosticsState === "connected" || diagnosticsState === "locked"));
}

function setAutomaticButton(enabled) {
  const value = enabled === true;
  automaticNode.dataset.enabled = value ? "true" : "false";
  automaticNode.setAttribute("aria-checked", String(value));
  // The label is fixed ("Ask to save logins on this site"); the tooltip names what a click does.
  automaticNode.title = value
    ? tr("popup_auto_turn_off")
    : tr("popup_auto_turn_on");
  automaticHintNode.textContent = value
    ? tr("popup_auto_on_hint")
    : tr("popup_auto_off_hint");
}

function actionableError(response, fallback) {
  if (response?.message) return response.message;
  return COMMAND_ERRORS[response?.error] || fallback;
}

function diagnosticError(response) {
  if (response?.message) return response.message;
  return DIAGNOSTIC_ERRORS[response?.error] || tr("popup_diag_default");
}

// ping is unauthenticated metadata: {ok, version, locked} only. It carries no
// lease, profile, protocol or integration-enabled flag. Whether the integration
// is paused (integration_disabled) or the protocol differs (version_mismatch)
// is reported by the first real action and shown on the page by content.js.
function applyDiagnostics(response) {
  lastDiagnostics = response;
  if (!response?.ok) {
    diagnosticsState = "offline";
    setConnectionStatus("offline", tr("popup_state_offline"), diagnosticError(response));
    updateFieldActionAvailability();
    return "offline";
  }
  if (response.locked === true) {
    diagnosticsState = "locked";
    setConnectionStatus("locked", tr("popup_state_locked"), tr("popup_locked_desc"));
    updateFieldActionAvailability();
    return "locked";
  }
  if (response.locked !== false) {
    diagnosticsState = "setup";
    setConnectionStatus("setup", tr("popup_state_setup"), tr("popup_setup_desc"));
    updateFieldActionAvailability();
    return "setup";
  }
  diagnosticsState = "connected";
  const version = typeof response.version === "string" && response.version ? tr("popup_version_suffix",response.version) : "";
  setConnectionStatus("connected", tr("popup_chip_unlocked"), tr("popup_ready_version",version));
  updateFieldActionAvailability();
  return "connected";
}

async function refreshConnection({ announce = false } = {}) {
  if (connectionRequest) return connectionRequest;
  gateActionNode.disabled = true;
  gateActionNode.setAttribute("aria-busy", "true");
  diagnosticsState = "checking";
  updateFieldActionAvailability();
  setConnectionStatus("checking", tr("popup_chip_checking"), tr("popup_checking_connection_desc"));
  connectionRequest = (async () => {
    try {
      const response = await api.runtime.sendMessage({ type: "diagnostics" });
      const state = applyDiagnostics(response);
      if (announce) {
        if (state === "connected") setStatus(tr("popup_refreshed_ready"), "success");
        else if (state === "locked") setStatus(tr("popup_refreshed_locked"), "info");
        else if (state === "setup") setStatus(tr("popup_refreshed_setup"), "error");
        else setStatus(tr("popup_connection_unavailable",diagnosticError(response)), "error");
      }
      return response;
    } catch {
      const response = { ok: false, error: "native_host_error" };
      applyDiagnostics(response);
      if (announce) setStatus(tr("popup_connection_unavailable",diagnosticError(response)), "error");
      return response;
    } finally {
      connectionRequest = null;
      gateActionNode.disabled = commandInFlight;
      gateActionNode.setAttribute("aria-busy", "false");
    }
  })();
  return connectionRequest;
}

async function automaticOrigins() {
  const result = await api.storage.local.get({ [AUTOMATIC_KEY]: [] });
  return Array.isArray(result[AUTOMATIC_KEY])
    ? result[AUTOMATIC_KEY].filter(value => typeof value === "string")
    : [];
}

async function updateAutomaticButton() {
  if (!currentTab) return false;
  try {
    const enabled = !(await automaticOrigins()).includes(new URL(currentTab.url).origin);
    setAutomaticButton(enabled);
    return enabled;
  } catch {
    setAutomaticButton(false);
    setStatus(tr("popup_auto_read_failed"), "error");
    return false;
  }
}

async function toggleAutomatic() {
  if (!currentTab) {
    setStatus(tr("popup_auto_need_page"), "error");
    return;
  }
  automaticNode.disabled = true;
  automaticNode.setAttribute("aria-busy", "true");
  try {
    const currentOrigin = new URL(currentTab.url).origin;
    const origins = await automaticOrigins();
    const enabled = !origins.includes(currentOrigin);
    const next = enabled ? [...origins, currentOrigin] : origins.filter(value => value !== currentOrigin);
    await api.storage.local.set({ [AUTOMATIC_KEY]: next });
    setAutomaticButton(!enabled);
    setStatus(
      enabled ? tr("popup_auto_now_off") : tr("popup_auto_now_on"),
      "success",
    );
  } catch {
    setStatus(tr("popup_auto_update_failed"), "error");
  } finally {
    automaticNode.disabled = !currentTab;
    automaticNode.setAttribute("aria-busy", "false");
  }
}

// Frames the content script may run in: the top frame plus iframes whose URL
// shares the tab's origin (the service worker re-checks the full ancestor
// chain before any native call). Cross-origin frames are never injected.
async function sameOriginFrameIds(tab) {
  const ids = [0];
  let frames = [];
  try { frames = (await api.webNavigation.getAllFrames({ tabId: tab.id })) || []; } catch { return ids; }
  let topOrigin;
  try { topOrigin = new URL(tab.url).origin; } catch { return ids; }
  for (const frame of frames) {
    if (!Number.isInteger(frame.frameId) || frame.frameId <= 0 || frame.errorOccurred) continue;
    try { if (new URL(frame.url).origin === topOrigin) ids.push(frame.frameId); } catch { /* opaque frame URL */ }
  }
  return ids.sort((a, b) => a - b);
}

// sourceButton: the control the user pressed when it is not the command's own
// button (the locked state's "Unlock in the desktop app" runs fill_current).
async function sendCommand(command, extra = {}, sourceButton = null) {
  if (commandInFlight) return false;
  if (!currentTab) {
    setStatus(tr("popup_need_login_page"), "error");
    return;
  }
  if (!fieldActionsReady()) {
    const message = diagnosticsState === "checking"
      ? tr("popup_wait_checking")
      : diagnosticsState === "locked"
        ? tr("popup_unlock_on_action")
        : diagnosticsState === "setup"
            ? tr("popup_finish_setup_refresh")
            : tr("popup_actions_unavailable");
    setStatus(message, diagnosticsState === "locked" ? "info" : "error");
    return;
  }
  commandInFlight = true;
  updateFieldActionAvailability();
  const buttonId = {fill_current:"fill", fill_identity:"identity", fill_card:"card", save_current:"save", generate_new:"generate"}[command];
  const button = sourceButton || document.getElementById(buttonId);
  button.setAttribute("aria-busy", "true");
  setStatus(tr("popup_looking",COMMAND_LABELS[command]), "info");
  let restoreFocus = false;
  try {
    const frameIds = await sameOriginFrameIds(currentTab);
    const files = ["api.js", "heuristics.js", "login-safety.js", "content.js"];
    try {
      await api.scripting.executeScript({ target: { tabId: currentTab.id, frameIds }, files });
    } catch {
      // A listed subframe may have navigated away meanwhile; the top frame alone is still valid.
      frameIds.splice(0, frameIds.length, 0);
      await api.scripting.executeScript({ target: { tabId: currentTab.id, frameIds }, files });
    }
    // Ask the top frame first, then each same-origin iframe, until one owns a matching field.
    let response = null;
    for (const frameId of frameIds) {
      try { response = await api.tabs.sendMessage(currentTab.id, { command, ...extra }, { frameId }); } catch { response = null; }
      if (response?.ok) break;
    }
    if (response?.ok) {
      setStatus(tr("popup_started",COMMAND_LABELS[command]), "success");
      setTimeout(() => window.close(), 500);
    } else {
      const fallback = command === "fill_current"
        ? tr("popup_fb_login")
        : command === "fill_identity"
          ? tr("popup_fb_identity")
        : command === "fill_card"
          ? tr("popup_cmd_card_form_not_found")
        : command === "save_current"
          ? tr("popup_fb_save")
          : tr("popup_fb_generate");
      setStatus(actionableError(response, fallback), "error");
      restoreFocus = true;
    }
  } catch {
    setStatus(tr("popup_page_unreachable"), "error");
    restoreFocus = true;
  } finally {
    commandInFlight = false;
    button.setAttribute("aria-busy", "false");
    updateFieldActionAvailability();
    // Disabling the focused button while the command runs makes browsers drop
    // keyboard focus. On recoverable failure, return it to the action that
    // needs attention after the action buttons are enabled again.
    if (restoreFocus && !button.disabled && typeof button.focus === "function") button.focus();
  }
}

// Phishing shield: the page's content script asks the app for the verdict
// (computed there with the saved origins, which never leave it) and returns
// it. No verdict (locked vault, no app) shows no state.
const SITE_STATES = {
  exact: () => tr("site_verified"),
  related: () => tr("site_related"),
  lookalike: () => tr("site_lookalike"),
  unknown: () => tr("site_new"),
};
async function refreshSiteState(tab) {
  let response = null;
  try { response = await api.tabs.sendMessage(tab.id, { command: "site_state" }, { frameId: 0 }); } catch { response = null; }
  const kind = response?.verdict?.kind;
  const label = Object.hasOwn(SITE_STATES, kind) ? SITE_STATES[kind]() : "";
  siteStateNode.textContent = label;
  siteStateNode.dataset.state = label ? kind : "";
  siteStateNode.hidden = !label;
}

// Fills every data-i18n element from the locale catalog; the English text in
// popup.html stays as the fallback. textContent only, never innerHTML.
function applyTranslations() {
  if (typeof document.querySelectorAll !== "function") return;
  for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = tr(el.dataset.i18n);
  for (const el of document.querySelectorAll("[data-i18n-aria-label]")) el.setAttribute("aria-label", tr(el.dataset.i18nAriaLabel));
  for (const el of document.querySelectorAll("[data-i18n-title]")) el.setAttribute("title", tr(el.dataset.i18nTitle));
}

async function initialize() {
  applyTranslations();
  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    const url = new URL(tab?.url || "");
    if (!tab || !["https:", "http:"].includes(url.protocol)) throw new Error("unsupported_page");
    currentTab = tab;
    siteNode.textContent = url.origin;
    setFieldActionsEnabled(false);
    setAutomaticAvailable(true);
    await Promise.all([refreshConnection(), updateAutomaticButton(), refreshSiteState(tab)]);
  } catch {
    currentTab = null;
    siteNode.textContent = tr("popup_page_unavailable");
    setPageActionsEnabled(false);
    updateLoginsGate();
    await refreshConnection();
  }
}

for (const [id, command] of [["fill", "fill_current"], ["identity", "fill_identity"], ["card", "fill_card"], ["save", "save_current"]]) {
  document.getElementById(id).addEventListener("click", () => sendCommand(command));
}
// "Generate password" opens the existing generator panel; its "Fill on page"
// sends generate_new with the value shown there.
generateNode.addEventListener("click", () => {
  generatorNode.open = !generatorNode.open;
  generateNode.setAttribute("aria-expanded", String(generatorNode.open));
  const target = generatorNode.open ? document.getElementById("gen-fill") : null;
  if (target && typeof target.focus === "function") target.focus();
});
generatorNode.addEventListener("toggle", () => generateNode.setAttribute("aria-expanded", String(generatorNode.open)));
// Locked: choosing an action is what makes the desktop app ask to unlock
// (opening the popup never unlocks). Offline / setup: check the app again.
gateActionNode.addEventListener("click", () => {
  if (gateActionNode.dataset.action === "unlock") return sendCommand("fill_current", {}, gateActionNode);
  return refreshConnection({ announce: true });
});
// Enter fills: the same as the Fill button (fills the only match, or opens this
// page's login chooser), unless focus is on another control.
document.addEventListener("keydown", event => {
  if (event.key !== "Enter" || event.defaultPrevented || event.isComposing) return;
  const target = event.target;
  if (target && target !== document.body && target !== document.documentElement && /^(BUTTON|INPUT|SELECT|TEXTAREA|SUMMARY|A)$/.test(target.tagName || "")) return;
  if (fillNode.disabled || loginsReadyNode.hidden) return;
  event.preventDefault();
  fillNode.click();
});
automaticNode.addEventListener("click", toggleAutomatic);
initialize();
