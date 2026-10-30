"use strict";

const statusNode = document.getElementById("status");
const siteNode = document.getElementById("site");
const siteHintNode = document.getElementById("site-hint");
const connectionCard = document.getElementById("connection-card");
const connectionTitleNode = document.getElementById("connection-title");
const connectionDescriptionNode = document.getElementById("connection-description");
const connectionNode = document.getElementById("connection");
const automaticNode = document.getElementById("automatic");
const automaticLabelNode = document.getElementById("automatic-label");
const automaticHintNode = document.getElementById("automatic-hint");
// Sites where the save prompt is turned off. Every other site asks by default.
const AUTOMATIC_KEY = "automatic_save_blocked_origins";
const FIELD_ACTION_IDS = ["fill", "identity", "card", "save", "generate"];
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

function setStatus(message, kind = "info") {
  statusNode.textContent = message || "";
  statusNode.dataset.kind = kind;
  statusNode.hidden = !message;
}

function setConnectionStatus(state, title, description) {
  connectionCard.dataset.state = state;
  connectionTitleNode.textContent = title;
  connectionDescriptionNode.textContent = description;
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

function updateActionGuidance() {
  if (!currentTab) return;
  const guidance = {
    checking: tr("popup_guidance_checking"),
    offline: tr("popup_guidance_offline"),
    setup: tr("popup_guidance_setup"),
    locked: tr("popup_guidance_locked"),
    connected: tr("popup_guidance_connected"),
  };
  siteHintNode.textContent = guidance[diagnosticsState] || guidance.checking;
}

function updateFieldActionAvailability() {
  setFieldActionsEnabled(diagnosticsState === "connected" || diagnosticsState === "locked");
  updateActionGuidance();
}

function fieldActionsReady() {
  return Boolean(currentTab && (diagnosticsState === "connected" || diagnosticsState === "locked"));
}

function setAutomaticButton(enabled) {
  const value = enabled === true;
  automaticNode.dataset.enabled = value ? "true" : "false";
  automaticNode.setAttribute("aria-pressed", String(value));
  automaticLabelNode.textContent = value
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
  setConnectionStatus("connected", tr("popup_state_connected"), tr("popup_ready_version",version));
  updateFieldActionAvailability();
  return "connected";
}

async function refreshConnection({ announce = false } = {}) {
  if (connectionRequest) return connectionRequest;
  connectionNode.disabled = true;
  connectionNode.setAttribute("aria-busy", "true");
  diagnosticsState = "checking";
  updateFieldActionAvailability();
  setConnectionStatus("checking", tr("popup_checking_connection"), tr("popup_checking_connection_desc"));
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
      connectionNode.disabled = false;
      connectionNode.setAttribute("aria-busy", "false");
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

async function sendCommand(command) {
  if (commandInFlight) return;
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
  const button = document.getElementById(buttonId);
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
      try { response = await api.tabs.sendMessage(currentTab.id, { command }, { frameId }); } catch { response = null; }
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
    updateActionGuidance();
    await Promise.all([refreshConnection(), updateAutomaticButton()]);
  } catch {
    currentTab = null;
    siteNode.textContent = tr("popup_page_unavailable");
    siteHintNode.textContent = tr("popup_page_unavailable_hint");
    setPageActionsEnabled(false);
    await refreshConnection();
  }
}

for (const [id, command] of [["fill", "fill_current"], ["identity", "fill_identity"], ["card", "fill_card"], ["save", "save_current"], ["generate", "generate_new"]]) {
  document.getElementById(id).addEventListener("click", () => sendCommand(command));
}
automaticNode.addEventListener("click", toggleAutomatic);
connectionNode.addEventListener("click", () => refreshConnection({ announce: true }));
initialize();
