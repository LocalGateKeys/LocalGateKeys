"use strict";
// The popup's list of this site's logins, the per-site "always use this
// popup" switch and the "Why no icon?" note. The popup is browser UI a page
// cannot cover or click, so listing titles and usernames here is safe; no
// password ever comes here. A login is filled by the page's content script
// through the usual checks (fill_current with the chosen login's id).
(() => {
  const $ = id => document.getElementById(id);
  if (typeof document.querySelector !== "function" || !$("site-logins")) return;
  const list = $("site-logins"), empty = $("site-logins-empty"), note = $("logins-note"), toggle = $("popup-only");
  const KEY = "popup_only_origins";
  let pageOrigin = null;

  async function activeOrigin() {
    try {
      const [tab] = await api.tabs.query({ active: true, currentWindow: true });
      const url = new URL(tab?.url || "");
      return ["https:", "http:"].includes(url.protocol) ? { tab, origin: url.origin } : null;
    } catch { return null; }
  }

  // Older apps answer unsupported: the list stays hidden and the Fill button
  // works as before. A locked vault shows the existing "unlock" state.
  async function loadLogins() {
    let reply = null;
    try { reply = await api.runtime.sendMessage({ type: "site_logins" }); } catch { reply = null; }
    if (!reply || reply.ok !== true || !Array.isArray(reply.logins)) return;
    list.replaceChildren();
    for (const login of reply.logins.slice(0, 20)) {
      if (!login || typeof login.entry_id !== "string") continue;
      const item = document.createElement("li"), button = document.createElement("button");
      button.type = "button"; button.className = "site-login";
      const title = document.createElement("span"), user = document.createElement("span");
      title.className = "login-title"; user.className = "login-user";
      title.textContent = (typeof login.title === "string" && login.title) || login.username || "";
      user.textContent = typeof login.username === "string" ? login.username : "";
      button.append(title, user);
      button.title = tr("popup_fill_button");
      button.addEventListener("click", () => sendCommand("fill_current", { entry_id: login.entry_id }, button));
      item.append(button);
      list.append(item);
    }
    const any = list.children.length > 0;
    list.hidden = !any;
    empty.hidden = any;
    if (any) note.textContent = tr("popup_site_logins_note");
  }

  function paintToggle(on) {
    toggle.setAttribute("aria-checked", String(on));
    $("popup-only-hint").textContent = on ? tr("popup_popup_only_on_hint") : tr("popup_popup_only_off_hint");
  }
  async function popupOnlyOrigins() {
    const stored = await api.storage.local.get({ [KEY]: [] });
    return Array.isArray(stored[KEY]) ? stored[KEY].filter(v => typeof v === "string") : [];
  }
  toggle.addEventListener("click", async () => {
    if (!pageOrigin) return;
    toggle.disabled = true;
    try {
      const origins = await popupOnlyOrigins();
      const on = !origins.includes(pageOrigin);
      await api.storage.local.set({ [KEY]: on ? [...origins, pageOrigin].slice(-1000) : origins.filter(v => v !== pageOrigin) });
      paintToggle(on);
    } catch { /* unchanged */ }
    finally { toggle.disabled = !pageOrigin; }
  });

  // Login frames from another site get no icon (the frame-chain rule). Name
  // their origins so the user knows where the form comes from: only frames
  // whose own content script reports a password field (not every ad or embed
  // the page holds), and with no advice to open them (final review L7).
  const FRAME_ASK_MS = 800, MAX_FRAMES_ASKED = 10;
  async function hasPasswordField(tabId, frameId) {
    let timer;
    try {
      const reply = await Promise.race([
        api.tabs.sendMessage(tabId, { command: "has_password_field" }, { frameId }),
        new Promise(resolve => { timer = setTimeout(() => resolve(null), FRAME_ASK_MS); }),
      ]);
      return reply?.ok === true && reply.password === true;
    } catch { return false; } finally { clearTimeout(timer); }
  }
  async function frameOrigins(tab, origin) {
    let frames = [];
    try { frames = (await api.webNavigation.getAllFrames({ tabId: tab.id })) || []; } catch { return; }
    const candidates = [];
    for (const frame of frames) {
      try {
        const url = new URL(frame.url);
        if (Number.isInteger(frame.frameId) && frame.frameId > 0 && !frame.errorOccurred && ["https:", "http:"].includes(url.protocol) && url.origin !== origin) candidates.push({ frameId: frame.frameId, origin: url.origin });
      } catch { /* opaque frame URL */ }
    }
    const asked = candidates.slice(0, MAX_FRAMES_ASKED);
    const found = await Promise.all(asked.map(c => hasPasswordField(tab.id, c.frameId)));
    const others = new Set(asked.filter((_, i) => found[i]).map(c => c.origin));
    if (!others.size) return;
    const line = $("frame-origin");
    line.textContent = tr("popup_frame_origin", [...others].slice(0, 3).join(", "));
    line.hidden = false;
  }

  (async () => {
    const page = await activeOrigin();
    if (!page) return;
    pageOrigin = page.origin;
    try { paintToggle((await popupOnlyOrigins()).includes(pageOrigin)); toggle.disabled = false; } catch { /* stays off */ }
    await Promise.all([loadLogins(), frameOrigins(page.tab, page.origin)]);
  })();
})();
