"use strict";
// The in-page panel, drawn in this extension page instead of in the page's
// DOM. content.js frames panel.html into the page (web-accessible; on
// Chromium with use_dynamic_url) and names the frame with a fresh random
// token. Everything here comes from and goes to the extension:
//
//   pull   asks for what to draw (title, text, rows). The service worker
//          relays it to the content script of this tab, which answers only
//          the token it issued and binds it to the first frame that asks.
//   size   reports the drawn height, so the content script sizes the frame.
//   event  reports the user's click on a row (with the check boxes and,
//          for the generator, the suggested password).
//
// No postMessage, no URL parameters, no listener for page messages: the page
// can neither read this document (cross-origin) nor talk to it. A click
// counts only when trusted, after the panel has been on screen for ARM_MS
// (no click-through on a panel that pops up under the pointer; the delay
// starts again whenever the frame turns visible again) and, where the browser
// reports it (IntersectionObserver v2), while the frame is really visible.
// The content script checks its own host at several points as well before it
// acts, and ignores clicks just after the panel moved. These checks make a
// lured click much harder; they are not a guarantee.
(() => {
  const ARM_MS = 500;
  const TOKEN = /^[0-9a-f]{32}$/;
  const token = TOKEN.test(window.name) ? window.name : "";
  // Read once: a document the page might later navigate this frame to finds
  // no token in the window name.
  window.name = "";
  const root = document.getElementById("root");
  if (!token || !root || window.top === window) return;

  let spec = null, shownAt = Infinity, visible = null, genValue = "", genOpts = null, input = null;
  const rows = new Map();
  const checks = {};

  const send = (type, extra = {}) => Promise.resolve()
    .then(() => api.runtime.sendMessage({ type, token, ...extra }))
    .catch(() => null);

  // IntersectionObserver v2: isVisible is false while anything covers the
  // frame or it is faded, transformed or filtered. Browsers without v2
  // (Firefox, Safari) leave it undefined and the check is skipped.
  const trackVisibility = typeof IntersectionObserverEntry === "function" && "isVisible" in IntersectionObserverEntry.prototype;
  // Chromium takes an observer's first reading when it starts observing. The
  // frame loads before content.js places its host (that happens when the
  // frame reports its size), so that reading is "not visible", and it was
  // seen to stay so on a list panel that never changes size: every mouse
  // click was then refused as tampering. Observe again once the host is
  // placed (after each size report); until the new reading arrives the
  // visibility is unknown and clicks are ignored, never let through.
  let observer = null;
  function watchVisibility() {
    if (!trackVisibility) return;
    try {
      observer?.disconnect();
      visible = null;
      observer = new IntersectionObserver(entries => {
        for (const entry of entries) {
          const now = entry.isVisible === true;
          // Turning visible (again) re-arms: a panel the page uncovers under
          // the pointer needs the same pause as a new one.
          if (now && visible !== true) shownAt = Math.max(shownAt === Infinity ? 0 : shownAt, performance.now());
          visible = now;
        }
      }, { trackVisibility: true, delay: 100, threshold: [1] });
      observer.observe(root);
    } catch { observer = null; visible = null; }
  }
  watchVisibility();

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };
  const SVG = "http://www.w3.org/2000/svg";
  function logoTile(logo) {
    if (!logo || typeof logo.hex !== "string" || !/^#[0-9a-f]{6}$/i.test(logo.hex) || typeof logo.path !== "string" || !/^[0-9a-z.,\- ]{1,20000}$/i.test(logo.path)) return null;
    const n = parseInt(logo.hex.slice(1), 16);
    const light = (0.299 * (n >> 16) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255 > 0.7;
    const tile = el("span", "logo");
    tile.style.background = logo.hex;
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    const path = document.createElementNS(SVG, "path");
    path.setAttribute("d", logo.path);
    path.setAttribute("fill", light ? "#111111" : "#ffffff");
    svg.append(path);
    tile.append(svg);
    return tile;
  }

  // The generator block of the new-password menu: a suggestion with a
  // refresh button, the length and the character groups. Changes are saved
  // as the popup generator's settings.
  function generator(options) {
    const G = globalThis.LGKGenerator;
    if (!G) return null;
    genOpts = { ...options, mode: "password" };
    const gen = el("div", "gen");
    const out = el("div", "gen-value"), again = el("button", "gen-again", "↻");
    again.type = "button";
    again.title = tr("gen_new");
    again.setAttribute("aria-label", again.title);
    const row = el("div", "gen-out");
    row.append(out, again);
    const lenRow = el("label", "gen-len"), slider = el("input"), lenValue = el("b");
    const lengthLabel = tr("gen_length");
    slider.type = "range"; slider.min = "8"; slider.max = "64";
    slider.setAttribute("aria-label", lengthLabel);
    lenRow.append(el("span", "", lengthLabel), slider, lenValue);
    const boxes = {}, checksRow = el("div", "gen-checks");
    for (const [key, label] of [["lowercase", "a–z"], ["uppercase", "A–Z"], ["digits", "0–9"], ["symbols", "!@#$"]]) {
      const l = el("label"), c = el("input");
      c.type = "checkbox";
      boxes[key] = c;
      l.append(c, document.createTextNode(" " + label));
      checksRow.append(l);
    }
    gen.append(row, lenRow, checksRow);
    const refresh = () => {
      slider.value = String(Math.min(64, Math.max(8, Number(genOpts.length) || 20)));
      lenValue.textContent = slider.value;
      for (const [k, c] of Object.entries(boxes)) c.checked = genOpts[k] !== false;
      try { genValue = G.password({ ...genOpts, length: Number(slider.value) }); } catch { genValue = ""; }
      out.textContent = genValue;
    };
    const change = patch => {
      genOpts = { ...genOpts, ...patch };
      if (!["lowercase", "uppercase", "digits", "symbols"].some(k => genOpts[k] !== false)) genOpts.lowercase = true;
      refresh();
      void Promise.resolve().then(() => api.storage.local.set({ generator_options: genOpts })).catch(() => {});
    };
    again.addEventListener("click", e => { if (!e.isTrusted) return; e.preventDefault(); refresh(); });
    slider.addEventListener("input", e => { if (e.isTrusted) change({ length: Number(slider.value) }); });
    for (const [k, c] of Object.entries(boxes)) c.addEventListener("change", e => { if (e.isTrusted) change({ [k]: c.checked }); });
    refresh();
    return gen;
  }

  function paintCheck(button, row) {
    button.setAttribute("aria-checked", String(!!checks[row.id]));
    button.querySelector(".tick").textContent = checks[row.id] ? "✓" : "";
  }

  function render(s) {
    spec = s;
    rows.clear();
    input = null;
    root.replaceChildren();
    const str = v => typeof v === "string" ? v : "";
    root.setAttribute("aria-label", str(s.title) || "LocalGateKeys");
    root.classList.toggle("list", s.fixed === true || (Array.isArray(s.rows) ? s.rows : []).some(r => r && (r.kind === "account" || r.kind === "check")));
    root.append(el("h3", "", str(s.title)), el("div", "origin", str(s.origin)), el("p", "", str(s.text)));
    if (s.generator && typeof s.generator === "object") {
      const gen = generator(s.generator);
      if (gen) root.append(gen);
    }
    for (const row of Array.isArray(s.rows) ? s.rows : []) {
      if (!row || typeof row.id !== "string") continue;
      if (row.kind === "note") { root.append(el("p", "note", str(row.label))); continue; }
      // One editable text row (the save panel's username). Its value goes
      // with the primary button's click; nothing is sent while typing.
      if (row.kind === "input" && !input) {
        const label = el("label", "field"), box = el("input");
        box.type = "text"; box.value = str(row.value).slice(0, 512); box.maxLength = 512;
        box.autocomplete = "off"; box.spellcheck = false;
        // Not a login field to the browser or other password managers:
        // Safari showed its AutoFill key in it (the "Username" label). A
        // neutral name and id, no AutoFill hints, and the usual opt-outs.
        box.name = box.id = "lgk-panel-value";
        for (const [k, v] of [["aria-autocomplete", "none"], ["autocapitalize", "off"], ["autocorrect", "off"], ["data-form-type", "other"],
          ["data-1p-ignore", ""], ["data-lpignore", "true"], ["data-bwignore", "true"]]) box.setAttribute(k, v);
        label.append(el("span", "", str(row.label)), box);
        root.append(label);
        input = box;
        continue;
      }
      rows.set(row.id, row);
      const b = el("button");
      b.type = "button";
      b.dataset.row = row.id;
      if (row.kind === "account") {
        b.className = "account";
        const label = el("span", "text");
        label.append(el("span", "", str(row.label)));
        if (str(row.secondary)) label.append(el("span", "secondary", row.secondary));
        for (const extra of Array.isArray(row.extra) ? row.extra : []) label.append(el("span", "secondary match", str(extra)));
        const tile = logoTile(row.logo);
        if (tile) { b.classList.add("has-logo"); b.append(tile); }
        b.append(label);
        if (str(row.action)) { const pill = el("span", "fill-pill", str(row.action)); pill.setAttribute("aria-hidden", "true"); b.append(pill); }
      } else if (row.kind === "check") {
        b.className = "account check";
        b.setAttribute("role", "checkbox");
        b.dataset.token = str(row.key);
        if (str(row.group)) { b.dataset.group = row.group; b.setAttribute("role", "radio"); }
        checks[row.id] = !!row.checked;
        b.append(el("span", "tick"), el("span", "", str(row.label)));
        paintCheck(b, row);
      } else {
        b.textContent = str(row.label);
        b.className = row.primary ? "primary" : "";
      }
      root.append(b);
    }
    const buttons = Array.from(root.querySelectorAll("button[data-row]"));
    const focus = s.focus === "primary" ? root.querySelector("button.primary[data-row]") || buttons[0] : s.focus === "first" ? buttons[0] : null;
    focus?.focus();
    shownAt = performance.now();
    reportSize();
  }

  let lastHeight = -1;
  function reportSize() {
    const height = Math.ceil(root.getBoundingClientRect().height);
    if (height === lastHeight) return;
    lastHeight = height;
    void send("ui_size", { height }).then(watchVisibility);
  }
  if (typeof ResizeObserver === "function") new ResizeObserver(() => { if (spec) reportSize(); }).observe(root);

  // Clicks (mouse, touch, and Enter or Space on a focused row, which the
  // browser turns into a trusted click with detail 0).
  root.addEventListener("click", e => {
    const b = e.target instanceof Element ? e.target.closest("button[data-row]") : null;
    if (!b || !spec) return;
    e.preventDefault();
    if (!e.isTrusted || performance.now() - shownAt < ARM_MS) return;
    if (trackVisibility && visible === null) return;
    const row = rows.get(b.dataset.row);
    if (!row) return;
    if (row.kind === "check" && visible !== false) {
      // Rows of one group are a choice of one (which saved login to update).
      if (str2(row.group)) {
        for (const [id, other] of rows) if (other.kind === "check" && other.group === row.group) { checks[id] = id === row.id; const ob = root.querySelector(`button[data-row="${id}"]`); if (ob) paintCheck(ob, other); }
      } else { checks[row.id] = !checks[row.id]; paintCheck(b, row); }
      return;
    }
    const event = { id: row.id, checks: { ...checks }, x: Math.round(e.clientX), y: Math.round(e.clientY), detail: Number(e.detail) || 0, visible: trackVisibility ? visible : null };
    if (row.primary && spec.generator && genValue) event.value = genValue;
    else if (row.primary && input) event.value = input.value.slice(0, 512);
    void send("ui_event", event);
  });
  const str2 = v => typeof v === "string" ? v : "";
  // Arrows, Home and End move between rows; Escape closes the panel.
  document.addEventListener("keydown", e => {
    if (!e.isTrusted || !spec) return;
    if (e.key === "Escape") { e.preventDefault(); void send("ui_event", { id: "__escape" }); return; }
    if (e.target === input) return;
    const buttons = Array.from(root.querySelectorAll("button[data-row]"));
    const i = buttons.indexOf(document.activeElement);
    const move = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: buttons.length - 1 }[e.key];
    if (move == null || !buttons.length) return;
    e.preventDefault();
    buttons[(move + buttons.length) % buttons.length].focus();
  });

  void send("ui_pull").then(reply => {
    if (reply && reply.ok === true && reply.spec && typeof reply.spec === "object") render(reply.spec);
  });
})();
