"use strict";
// Lookalike-domain classifier: the same algorithm as src/localvault/lookalike.py
// (read its module docstring for the verdicts and their order). Shared vectors:
// tests/vectors/lookalike/cases.json. No network, storage or extension API use:
// the caller passes the registrable-domain rules from psl-min.json to setRules.
(() => {
  const MIN_EDIT_LABEL = 5;
  // 1 edit for a saved label of 5-8 characters, 2 from 9 (github/gitlab, apple/ample differ).
  const SHORT_EDIT_DISTANCE = 1, LONG_EDIT_LABEL = 9, LONG_EDIT_DISTANCE = 2;
  // In a 5-8 character label a single substitution only counts between these look-alike
  // characters; an added, dropped or swapped letter always counts. Same text as lookalike.py.
  const VISUAL_PAIRS_TABLE = "0o 1i 1l 2z 5s 8b 9g 9q gq il uv nm";
  const VISUAL_PAIRS = new Set(VISUAL_PAIRS_TABLE.split(" ").flatMap(p => [p, p[1] + p[0]]));
  // Homoglyphs folded onto the Latin letter they imitate. Byte-identical with lookalike.py.
  const CONFUSABLES_TABLE =
    "0430a 0441c 0501d 0435e 04bbh 0456i 0458j 043ak 04cfl 043eo 0440p 051bq 0455s 0443y 0445x 051dw 04afy " +
    "03b1a 03b5e 03b9i 03bak 03bdv 03bfo 03c1p 03c4t 03c5u 03c7x 03b3y " +
    "0585o 057du 0581g 0570h 0578n 0566q " +
    "0131i 0251a 0261g 0237j";
  const CONFUSABLES = new Map(CONFUSABLES_TABLE.split(" ").map(item =>
    [String.fromCodePoint(parseInt(item.slice(0, 4), 16)), item.slice(4)]));
  const SCRIPTS = [
    ["HAN", /\p{Script=Han}/u], ["LATIN", /\p{Script=Latin}/u], ["CYRILLIC", /\p{Script=Cyrillic}/u],
    ["GREEK", /\p{Script=Greek}/u], ["ARMENIAN", /\p{Script=Armenian}/u], ["HEBREW", /\p{Script=Hebrew}/u],
    ["ARABIC", /\p{Script=Arabic}/u], ["HIRAGANA", /\p{Script=Hiragana}/u], ["KATAKANA", /\p{Script=Katakana}/u],
    ["HANGUL", /\p{Script=Hangul}/u], ["BOPOMOFO", /\p{Script=Bopomofo}/u], ["THAI", /\p{Script=Thai}/u], ["DEVANAGARI", /\p{Script=Devanagari}/u],
    ["GEORGIAN", /\p{Script=Georgian}/u], ["CHEROKEE", /\p{Script=Cherokee}/u],
  ];
  // Japanese marks with one fixed script in both runtimes (h = Han, k = Katakana). Same text as lookalike.py.
  const SCRIPT_TABLE = "3005h 3006h 3007h 303bh 309bk 309ck 30a0k 30fbk 30fck";
  const SCRIPT_FIXED = new Map(SCRIPT_TABLE.split(" ").map(item =>
    [String.fromCodePoint(parseInt(item.slice(0, 4), 16)), item[4] === "h" ? "HAN" : "KATAKANA"]));
  // UTS #39 "highly restrictive": one script, or Latin with one of these sets.
  const ALLOWED_MIXES = [
    new Set(["LATIN", "HAN", "HIRAGANA", "KATAKANA"]),
    new Set(["LATIN", "HAN", "BOPOMOFO"]),
    new Set(["LATIN", "HAN", "HANGUL"]),
  ];
  const MARK = /^\p{M}$/u;
  const LETTER_OR_NUMBER = /^[\p{L}\p{N}]$/u;
  const RANKS = { "same-origin": 0, "same-host": 1, "same-site": 2, "homoglyph": 3, "other-suffix": 4,
    "embedded": 5, "edit-distance": 6 };
  const KIND = { "same-origin": "exact", "same-host": "related", "same-site": "related" };

  let rules = null;

  function setRules(data) {
    const okList = v => Array.isArray(v) && v.every(x => typeof x === "string");
    if (!data || typeof data !== "object" || !data.normal || typeof data.normal !== "object" ||
        Array.isArray(data.normal) || !okList(data.wildcard) || !okList(data.exception) ||
        !Object.values(data.normal).every(v => typeof v === "string")) {
      throw new Error("psl: malformed rules");
    }
    const normal = new Set();
    for (const [last, heads] of Object.entries(data.normal)) {
      for (const head of heads.split(" ")) if (head) normal.add(`${head}.${last}`);
    }
    rules = { normal, wildcard: new Set(data.wildcard), exception: new Set(data.exception) };
  }

  // Public suffix of an A-label host (PSL algorithm, as origin.public_suffix).
  function publicSuffix(host) {
    const labels = host.split(".");
    const n = labels.length;
    for (let i = 0; i < n; i++) {
      if (rules.exception.has(labels.slice(i).join("."))) return labels.slice(i + 1).join(".");
    }
    for (let i = 0; i < n; i++) {
      if (rules.normal.has(labels.slice(i).join("."))) return labels.slice(i).join(".");
      if (i + 1 < n && rules.wildcard.has(labels.slice(i + 1).join("."))) return labels.slice(i).join(".");
    }
    return labels[n - 1];
  }

  // RFC 3492 decoder for the part after "xn--". Throws on malformed input.
  function punycodeDecode(input) {
    const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700;
    const adapt = (delta, points, first) => {
      delta = first ? Math.floor(delta / DAMP) : delta >> 1;
      delta += Math.floor(delta / points);
      let k = 0;
      while (delta > ((BASE - TMIN) * TMAX) >> 1) { delta = Math.floor(delta / (BASE - TMIN)); k += BASE; }
      return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
    };
    const digit = c => c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : BASE;
    const output = [];
    const basic = Math.max(input.lastIndexOf("-"), 0);
    for (let j = 0; j < basic; j++) {
      const c = input.charCodeAt(j);
      if (c >= 0x80) throw new RangeError("punycode: not basic");
      output.push(c);
    }
    let n = 128, bias = 72, i = 0;
    for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      const oldi = i;
      let w = 1;
      for (let k = BASE; ; k += BASE) {
        if (index >= input.length) throw new RangeError("punycode: truncated");
        const d = digit(input.charCodeAt(index++));
        if (d >= BASE) throw new RangeError("punycode: bad digit");
        i += d * w;
        if (i > 0x7fffffff) throw new RangeError("punycode: overflow");
        const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
        if (d < t) break;
        w *= BASE - t;
      }
      const points = output.length + 1;
      bias = adapt(i - oldi, points, oldi === 0);
      n += Math.floor(i / points);
      i %= points;
      if (n > 0x10ffff) throw new RangeError("punycode: out of range");
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  const decodeLabel = label => label.startsWith("xn--") ? punycodeDecode(label.slice(4)) : label;

  function parse(value, bareHostOk) {
    if (typeof value !== "string" || !value || value.length > 4096) return null;
    if (/[\s\x00-\x1f]/u.test(value)) return null;
    if (bareHostOk && !value.includes("://")) value = "https://" + value;
    let url;
    try { url = new URL(value); } catch { return null; }
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (url.username || url.password) return null;
    // Read the authority the way lookalike.py (urlsplit) does: it needs "//", and a "%" (the
    // URL parser would percent-decode it) or a backslash (the URL parser reads it as "/") is refused.
    if (!/^https?:\/\//i.test(value)) return null;
    if (/[%\\]/.test(value.slice(value.indexOf("//") + 2).split(/[/?#]/)[0])) return null;
    const scheme = url.protocol.slice(0, -1);
    const port = url.port ? Number(url.port) : null;
    let host = url.hostname;
    if (host.startsWith("[")) {
      host = host.slice(1, -1);
      return { scheme, host, port, ip: true, registrable: host, sub: "", label: host, labels: [host] };
    }
    if (host.endsWith(".")) host = host.slice(0, -1);
    if (!host || host.split(".").some(label => !label)) return null;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      return { scheme, host, port, ip: true, registrable: host, sub: "", label: host, labels: [host] };
    }
    let labels;
    try {
      labels = host.split(".").map(decodeLabel);
      // Browsers refuse a host whose punycode does not round-trip through UTS-46.
      if (new URL("https://" + labels.join(".")).hostname !== host) return null;
    } catch { return null; }
    const suffix = rules && host.includes(".") ? publicSuffix(host) : "";
    if (!suffix || suffix === host) {
      return { scheme, host, port, ip: false, registrable: host, sub: "", label: "", labels };
    }
    const head = host.slice(0, -suffix.length - 1);
    const cut = head.lastIndexOf(".");
    const sub = cut < 0 ? "" : head.slice(0, cut);
    const regLabel = head.slice(cut + 1);
    return { scheme, host, port, ip: false, registrable: `${regLabel}.${suffix}`, sub,
      label: labels[sub ? sub.split(".").length : 0], labels };
  }

  function skeleton(label) {
    let out = "";
    for (const ch of label.toLowerCase().normalize("NFKD")) {
      if (MARK.test(ch)) continue;
      out += CONFUSABLES.get(ch) ?? ch;
    }
    return out;
  }

  function script(ch) {
    if (ch.charCodeAt(0) < 0x80) return /[a-z]/i.test(ch) ? "LATIN" : null;
    if (SCRIPT_FIXED.has(ch)) return SCRIPT_FIXED.get(ch);
    if (!LETTER_OR_NUMBER.test(ch)) return null; // marks, punctuation, symbols, emoji
    for (const [name, re] of SCRIPTS) if (re.test(ch)) return name;
    return "OTHER";
  }

  function mixedScript(label) {
    const scripts = new Set();
    for (const ch of label) {
      const s = script(ch);
      if (s) scripts.add(s);
    }
    return scripts.size > 1 && !ALLOWED_MIXES.some(allowed => [...scripts].every(s => allowed.has(s)));
  }

  // For labels one edit apart: is that edit a lookalike edit (see VISUAL_PAIRS)?
  function shortEditCounts(a, b) {
    a = Array.from(a); b = Array.from(b);
    if (a.length !== b.length) return true;
    const diff = [];
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) diff.push(i);
    if (diff.length === 1) return VISUAL_PAIRS.has(a[diff[0]] + b[diff[0]]);
    return true; // an adjacent transposition
  }

  // Damerau-Levenshtein distance, optimal string alignment variant, on code points.
  function osaDistance(a, b) {
    a = Array.from(a); b = Array.from(b);
    const rows = [Array.from({ length: b.length + 1 }, (_, j) => j)];
    for (let i = 1; i <= a.length; i++) {
      const row = [i];
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        row[j] = Math.min(rows[i - 1][j] + 1, row[j - 1] + 1, rows[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          row[j] = Math.min(row[j], rows[i - 2][j - 2] + 1);
        }
      }
      rows.push(row);
    }
    return rows[a.length][b.length];
  }

  function compare(site, saved) {
    if (site.host === saved.host) {
      return site.scheme === saved.scheme && site.port === saved.port ? ["same-origin", 0] : ["same-host", 0];
    }
    if (site.ip || saved.ip) return null;
    if (site.registrable === saved.registrable) return ["same-site", 0];
    if (!site.label || !saved.label) return null;
    const mine = skeleton(site.label), theirs = skeleton(saved.label);
    if (mine === theirs && site.label !== saved.label) return ["homoglyph", 0];
    const mineLen = Array.from(mine).length, theirLen = Array.from(theirs).length;
    const longEnough = theirLen >= MIN_EDIT_LABEL;
    if (longEnough && site.label === saved.label) return ["other-suffix", 0];
    if (site.sub && `.${site.sub}.`.includes(`.${saved.registrable}.`)) return ["embedded", 0];
    const limit = theirLen >= LONG_EDIT_LABEL ? LONG_EDIT_DISTANCE : SHORT_EDIT_DISTANCE;
    if (longEnough && Math.abs(mineLen - theirLen) <= limit) {
      const distance = osaDistance(mine, theirs);
      if (distance <= limit && (limit > SHORT_EDIT_DISTANCE || shortEditCounts(mine, theirs))) {
        return ["edit-distance", distance];
      }
    }
    return null;
  }

  const verdict = (kind, matched, reason) => Object.freeze({ kind, matched, reason });

  function classify(origin, savedOrigins) {
    const site = parse(origin, false);
    if (!site) return verdict("unknown", null, "invalid-origin");
    const list = savedOrigins && typeof savedOrigins !== "string" && typeof savedOrigins[Symbol.iterator] === "function"
      ? Array.from(savedOrigins) : [];
    let best = null;
    list.forEach((raw, index) => {
      const saved = parse(raw, true);
      if (!saved) return;
      const found = compare(site, saved);
      if (!found) return;
      const [reason, distance] = found;
      const key = [RANKS[reason], distance, index];
      if (!best || key[0] < best.key[0] || (key[0] === best.key[0] && (key[1] < best.key[1] ||
          (key[1] === best.key[1] && key[2] < best.key[2])))) {
        best = { key, reason, matched: raw };
      }
    });
    if (best) return verdict(KIND[best.reason] || "lookalike", best.matched, best.reason);
    if (!site.ip && site.labels.some(mixedScript)) return verdict("lookalike", null, "mixed-script");
    return verdict("unknown", null, "no-match");
  }

  globalThis.LGKLookalike = Object.freeze({ classify, setRules, punycodeDecode, osaDistance });
})();
