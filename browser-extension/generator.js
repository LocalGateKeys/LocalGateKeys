"use strict";
// Password and passphrase generator for the popup. Mirrors the desktop app's
// password_tools.generate_password / generate_passphrase: same character
// groups, look-alike set, minimum one of each chosen group, EFF word list.
// Randomness: crypto.getRandomValues with rejection sampling (no modulo bias).
(() => {
  const DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?";
  const AMBIGUOUS = new Set("Il1O0o|`'\"");
  const SEPARATORS = { dash: "-", space: " ", dot: ".", underscore: "_", none: "" };
  const LIMITS = Object.freeze({ lengthMin: 8, lengthMax: 128, wordsMin: 3, wordsMax: 12 });
  const DEFAULTS = Object.freeze({
    mode: "password", length: 20, lowercase: true, uppercase: true, digits: true, symbols: true,
    avoidAmbiguous: true, words: 6, separator: "dash", capitalize: false, appendNumber: false,
  });

  function randomBelow(n) {
    if (!Number.isInteger(n) || n < 1 || n > 0x100000000) throw new RangeError("bad range");
    const limit = Math.floor(0x100000000 / n) * n;
    const buf = new Uint32Array(1);
    for (;;) { crypto.getRandomValues(buf); if (buf[0] < limit) return buf[0] % n; }
  }
  const pick = s => s[randomBelow(s.length)];
  function shuffle(a) { for (let i = a.length - 1; i > 0; i--) { const j = randomBelow(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }
  const int = (v, lo, hi, d) => (typeof v === "number" && Number.isFinite(v)) ? Math.max(lo, Math.min(hi, Math.round(v))) : d;
  const bool = (v, d) => typeof v === "boolean" ? v : d;

  // Coerce stored or UI values into valid options (never throws).
  function normalize(raw) {
    const r = raw && typeof raw === "object" ? raw : {};
    return {
      mode: r.mode === "passphrase" ? "passphrase" : "password",
      length: int(r.length, LIMITS.lengthMin, LIMITS.lengthMax, DEFAULTS.length),
      lowercase: bool(r.lowercase, true), uppercase: bool(r.uppercase, true),
      digits: bool(r.digits, true), symbols: bool(r.symbols, true),
      avoidAmbiguous: bool(r.avoidAmbiguous, true),
      words: int(r.words, LIMITS.wordsMin, LIMITS.wordsMax, DEFAULTS.words),
      separator: Object.hasOwn(SEPARATORS, r.separator) ? r.separator : DEFAULTS.separator,
      capitalize: bool(r.capitalize, false), appendNumber: bool(r.appendNumber, false),
    };
  }

  function password(opts) {
    const o = normalize(opts);
    const keep = s => Array.from(s).filter(c => !(o.avoidAmbiguous && AMBIGUOUS.has(c))).join("");
    const groups = [];
    if (o.lowercase) groups.push(keep("abcdefghijklmnopqrstuvwxyz"));
    if (o.uppercase) groups.push(keep("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    if (o.digits) groups.push(keep("0123456789"));
    if (o.symbols) groups.push(keep(DEFAULT_SYMBOLS));
    if (!groups.length) throw new Error("no_group");
    const chars = groups.map(pick);
    const pool = groups.join("");
    while (chars.length < o.length) chars.push(pick(pool));
    return shuffle(chars).join("");
  }

  function passphrase(opts, words) {
    const o = normalize(opts);
    if (!Array.isArray(words) || words.length < 1000) throw new Error("no_words");
    let chosen = Array.from({ length: o.words }, () => pick(words));
    if (o.capitalize) chosen = chosen.map(w => w.charAt(0).toUpperCase() + w.slice(1));
    let phrase = chosen.join(SEPARATORS[o.separator]);
    if (o.appendNumber) phrase += String(randomBelow(90) + 10);
    return phrase;
  }

  function parseWords(text) {
    return String(text || "").split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#"));
  }

  globalThis.LGKGenerator = Object.freeze({ DEFAULTS, LIMITS, SEPARATORS, normalize, password, passphrase, parseWords, randomBelow });
})();
