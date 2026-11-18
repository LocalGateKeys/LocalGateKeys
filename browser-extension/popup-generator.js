"use strict";
// Generator panel of the popup. Works offline and without the desktop app:
// values are made locally (generator.js) and never sent anywhere except the
// current page, and only when you press Fill on page (or Generate password).
(() => {
  const G = globalThis.LGKGenerator;
  const $ = id => document.getElementById(id);
  if (!G || typeof document.querySelector !== "function" || !$("generator")) return;
  const KEY = "generator_options";
  const panel = $("generator"), valueNode = $("gen-value");
  const checks = { lowercase: "gen-lowercase", uppercase: "gen-uppercase", digits: "gen-digits", symbols: "gen-symbols",
    avoidAmbiguous: "gen-ambiguous", capitalize: "gen-capitalize", appendNumber: "gen-number" };
  let options = G.normalize(G.DEFAULTS);
  let wordsPromise = null;
  let current = "";

  function loadWords() {
    if (!wordsPromise) {
      wordsPromise = fetch(api.runtime.getURL("wordlist.txt")).then(r => r.text()).then(G.parseWords)
        .catch(() => { wordsPromise = null; return []; });
    }
    return wordsPromise;
  }

  function render() {
    panel.dataset.genMode = options.mode;
    $("gen-mode-password").setAttribute("aria-selected", String(options.mode === "password"));
    $("gen-mode-passphrase").setAttribute("aria-selected", String(options.mode === "passphrase"));
    $("gen-length").value = String(options.length); $("gen-length-value").textContent = String(options.length);
    $("gen-words").value = String(options.words); $("gen-words-value").textContent = String(options.words);
    $("gen-separator").value = options.separator;
    for (const [key, id] of Object.entries(checks)) $(id).checked = options[key];
  }

  async function make(opts = options) {
    if (opts.mode === "passphrase") return G.passphrase(opts, await loadWords());
    return G.password(opts);
  }

  async function regenerate() {
    try {
      current = await make();
      valueNode.textContent = current;
    } catch {
      current = "";
      valueNode.textContent = tr("gen_pick_group");
    }
    $("gen-copy").disabled = $("gen-fill").disabled = !current;
  }

  async function save() {
    try { await api.storage.local.set({ [KEY]: options }); } catch { /* settings stay for this popup only */ }
  }

  function update(patch) {
    options = G.normalize({ ...options, ...patch });
    // At least one character group stays on: unticking the last one is undone.
    if (!options.lowercase && !options.uppercase && !options.digits && !options.symbols) options.lowercase = true;
    render(); void save(); void regenerate();
  }

  $("gen-mode-password").addEventListener("click", () => update({ mode: "password" }));
  $("gen-mode-passphrase").addEventListener("click", () => update({ mode: "passphrase" }));
  $("gen-length").addEventListener("input", e => update({ length: Number(e.target.value) }));
  $("gen-words").addEventListener("input", e => update({ words: Number(e.target.value) }));
  $("gen-separator").addEventListener("change", e => update({ separator: e.target.value }));
  for (const [key, id] of Object.entries(checks)) $(id).addEventListener("change", e => update({ [key]: e.target.checked }));
  $("gen-refresh").addEventListener("click", () => void regenerate());
  $("gen-copy").addEventListener("click", async () => {
    if (!current) return;
    try { await navigator.clipboard.writeText(current); } catch { setStatus(tr("gen_copy_failed"), "error"); return; }
    startClearCountdown();
  });
  // While the popup stays open the copied value is cleared from the clipboard
  // after CLEAR_SECONDS, with the countdown shown. A closed popup cannot clear
  // it (the extension has no clipboard permission outside this page).
  const CLEAR_SECONDS = 30;
  let clearTimer = null;
  function startClearCountdown() {
    clearInterval(clearTimer);
    let left = CLEAR_SECONDS;
    setStatus(tr("popup_clipboard_clears", String(left)), "success");
    clearTimer = setInterval(async () => {
      left -= 1;
      if (left > 0) { setStatus(tr("popup_clipboard_clears", String(left)), "success"); return; }
      clearInterval(clearTimer); clearTimer = null;
      try { await navigator.clipboard.writeText(""); setStatus(tr("popup_clipboard_cleared"), "info"); } catch { setStatus("", "info"); }
    }, 1000);
  }
  $("gen-fill").addEventListener("click", () => { if (current) void sendCommand("generate_new", { value: current }); });
  panel.addEventListener("toggle", () => { if (panel.open && !current) void regenerate(); });

  // The quick "Generate password" action fills a fresh value with these settings.
  globalThis.lgkGeneratedValue = async () => { try { return await make(); } catch { return null; } };

  (async () => {
    try { options = G.normalize((await api.storage.local.get({ [KEY]: G.DEFAULTS }))[KEY]); } catch { /* defaults */ }
    render();
    if (panel.open) void regenerate();
  })();
})();
