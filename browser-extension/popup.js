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
  fill_current: "Fill login",
  fill_identity: "Fill identity",
  fill_card: "Fill card",
  save_current: "Save login",
  generate_new: "Generate password",
};
const DIAGNOSTIC_ERRORS = {
  agent_offline: "Open LocalGateKeys, repair the browser connection, then try again.",
  agent_state_missing: "Finish choosing a profile in LocalGateKeys, then try again.",
  agent_state_invalid: "Restart LocalGateKeys and repair the browser connection.",
  agent_unavailable: "Restart LocalGateKeys, then refresh the connection.",
  agent_connection_lost: "The bridge disconnected. Repair the browser connection and try again.",
  version_mismatch: "Update the extension and LocalGateKeys, then restart both.",
  integration_disabled: "Browser integration is paused. Re-enable it in LocalGateKeys Settings.",
  native_host_error: "The native host could not be reached. Repair the browser connection in LocalGateKeys.",
  timeout: "The bridge took too long to respond. Close any desktop prompt and try again.",
};
const COMMAND_ERRORS = {
  not_found: "No saved login was found for this site. Save a login first or check its fill policy.",
  session_changed: "The vault is locked or the profile changed. Click Fill login again to continue.",
  integration_disabled: "Browser integration is paused. Re-enable it in LocalGateKeys Settings.",
  destination_changed: "This page changed. Open the popup again on the intended login form.",
  busy: "Finish the open LocalGateKeys prompt, then try again.",
  agent_offline: "LocalGateKeys is offline. Open the desktop app and repair the browser connection.",
  identity_not_found: "No identity field was found on this page. Open a contact or address form and try again.",
  invalid_identity_fields: "The page requested an unsupported identity field. Choose contact or address fields only.",
  user_cancelled: "The fill was cancelled before any field was released.",
  card_not_found: "No payment card is saved in this profile. Add a card in LocalGateKeys first.",
  card_form_not_found: "No payment form was found on this page. Open a checkout form with a card-number field and try again.",
  invalid_card_fields: "The page requested an unsupported card field. Choose card fields only.",
  origin_mismatch: "This page changed origin. Open the extension again on the intended page.",
  version_mismatch: "Update and reload the extension and LocalGateKeys before filling identity fields.",
  gesture_nonce_invalid: "The click expired or belongs to another page. Choose the action again.",
  gesture_nonce_required: "Update and reload the extension: this action needs a fresh gesture nonce.",
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
    checking: "Checking LocalGateKeys before enabling this page's actions.",
    offline: "Reconnect LocalGateKeys to use this site's actions.",
    setup: "Finish LocalGateKeys setup before using this site's actions.",
    locked: "Choose an action to request unlock; nothing fills automatically.",
    connected: "Only this site's origin is checked. Nothing fills until you choose an action.",
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
    ? "Turn off save prompts on this site"
    : "Turn on save prompts on this site";
  automaticHintNode.textContent = value
    ? "On: you're asked after a successful sign-in here"
    : "Off: LocalGateKeys won't offer to save on this site";
}

function actionableError(response, fallback) {
  if (response?.message) return response.message;
  return COMMAND_ERRORS[response?.error] || fallback;
}

function diagnosticError(response) {
  if (response?.message) return response.message;
  return DIAGNOSTIC_ERRORS[response?.error] || "Open LocalGateKeys and repair the browser connection, then try again.";
}

// ping is unauthenticated metadata: {ok, version, locked} only. It carries no
// lease, profile, protocol or integration-enabled flag. Whether the integration
// is paused (integration_disabled) or the protocol differs (version_mismatch)
// is reported by the first real action and shown on the page by content.js.
function applyDiagnostics(response) {
  if (!response?.ok) {
    diagnosticsState = "offline";
    setConnectionStatus("offline", "Offline", diagnosticError(response));
    updateFieldActionAvailability();
    return "offline";
  }
  if (response.locked === true) {
    diagnosticsState = "locked";
    setConnectionStatus("locked", "Locked", "Choose an action to continue; the desktop app will ask before unlocking.");
    updateFieldActionAvailability();
    return "locked";
  }
  if (response.locked !== false) {
    diagnosticsState = "setup";
    setConnectionStatus("setup", "Setup required", "LocalGateKeys did not report a ready browser profile. Finish setup, then refresh.");
    updateFieldActionAvailability();
    return "setup";
  }
  diagnosticsState = "connected";
  const version = typeof response.version === "string" && response.version ? ` (LocalGateKeys ${response.version})` : "";
  setConnectionStatus("connected", "Connected", `LocalGateKeys is ready${version}. Nothing is unlocked until you choose an action.`);
  updateFieldActionAvailability();
  return "connected";
}

async function refreshConnection({ announce = false } = {}) {
  if (connectionRequest) return connectionRequest;
  connectionNode.disabled = true;
  connectionNode.setAttribute("aria-busy", "true");
  diagnosticsState = "checking";
  updateFieldActionAvailability();
  setConnectionStatus("checking", "Checking connection…", "Contacting LocalGateKeys without unlocking your vault.");
  connectionRequest = (async () => {
    try {
      const response = await api.runtime.sendMessage({ type: "diagnostics" });
      const state = applyDiagnostics(response);
      if (announce) {
        if (state === "connected") setStatus("Connection refreshed. LocalGateKeys is ready.", "success");
        else if (state === "locked") setStatus("Connection refreshed. Unlock will happen only after you choose an action.", "info");
        else if (state === "setup") setStatus("Connection refreshed. Finish LocalGateKeys setup, then refresh.", "error");
        else setStatus(`Connection unavailable. ${diagnosticError(response)}`, "error");
      }
      return response;
    } catch {
      const response = { ok: false, error: "native_host_error" };
      applyDiagnostics(response);
      if (announce) setStatus(`Connection unavailable. ${diagnosticError(response)}`, "error");
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
    setStatus("Could not read this site's automatic-save setting. Try again.", "error");
    return false;
  }
}

async function toggleAutomatic() {
  if (!currentTab) {
    setStatus("Open an http or https page before changing automatic save.", "error");
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
      enabled ? "Automatic save is off for this site." : "Automatic save is on. You will be asked before a login is saved.",
      "success",
    );
  } catch {
    setStatus("Could not update automatic save for this site. Try again.", "error");
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
    setStatus("Open an http or https page with a login form first.", "error");
    return;
  }
  if (!fieldActionsReady()) {
    const message = diagnosticsState === "checking"
      ? "Still checking LocalGateKeys. Wait for the connection status, then try again."
      : diagnosticsState === "locked"
        ? "Unlock is requested only after you choose a field action."
        : diagnosticsState === "setup"
            ? "Finish LocalGateKeys setup, then refresh the connection before using field actions."
            : "Field actions are unavailable. Open LocalGateKeys and repair the browser connection, then refresh.";
    setStatus(message, diagnosticsState === "locked" ? "info" : "error");
    return;
  }
  commandInFlight = true;
  updateFieldActionAvailability();
  const buttonId = {fill_current:"fill", fill_identity:"identity", fill_card:"card", save_current:"save", generate_new:"generate"}[command];
  const button = document.getElementById(buttonId);
  button.setAttribute("aria-busy", "true");
  setStatus(`${COMMAND_LABELS[command]} is looking for supported fields…`, "info");
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
      setStatus(`${COMMAND_LABELS[command]} started on this page.`, "success");
      setTimeout(() => window.close(), 500);
    } else {
      const fallback = command === "fill_current"
        ? "No supported login field was found. Open a sign-in form and try again."
        : command === "fill_identity"
          ? "No supported contact or address field was found. Open an identity form and try again."
        : command === "fill_card"
          ? "No payment form was found on this page. Open a checkout form with a card-number field and try again."
        : command === "save_current"
          ? "No current login field was found. Enter a login, then try again."
          : "No unambiguous new-password fields were found. Open a sign-up or password-change form and try again.";
      setStatus(actionableError(response, fallback), "error");
      restoreFocus = true;
    }
  } catch {
    setStatus("This page could not be reached. Reload the page and try again.", "error");
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

async function initialize() {
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
    siteNode.textContent = "This page is not available to LocalGateKeys.";
    siteHintNode.textContent = "Open a standard http or https login page to use these actions.";
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
