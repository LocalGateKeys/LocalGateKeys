// The Markdown subset for notes (display only). The grammar and the node shapes are pinned by
// tests/vectors/markdown/cases.json and described in tests/vectors/markdown/README.md; the Swift and
// Kotlin parsers must return the same nodes for every case. Nothing here ever produces HTML.

export const MAX_CHARS = 20000;

const isBlank = (line) => /^[ \t]*$/.test(line);
const trim = (s) => s.replace(/^[ \t]+|[ \t]+$/g, '');
const isSpace = (c) => c === ' ' || c === '\t' || c === '\n';

function listItem(line) {
  if (line.startsWith('- [ ] ')) return { kind: 'todo', done: false, text: line.slice(6) };
  if (line.startsWith('- [x] ') || line.startsWith('- [X] ')) return { kind: 'todo', done: true, text: line.slice(6) };
  if (line.startsWith('- ') || line.startsWith('* ')) return { kind: 'ul', text: line.slice(2) };
  const m = /^[0-9]+\. /.exec(line);
  return m ? { kind: 'ol', text: line.slice(m[0].length) } : null;
}

/** Text -> block nodes. Never throws; any input gives a node list. */
export function parseMarkdown(text) {
  const src = String(text ?? '').replace(/\r\n?/g, '\n');
  if (src.length > MAX_CHARS) return [{ t: 'p', c: [{ t: 'text', v: src }] }];
  const lines = src.split('\n');
  const out = [];
  let para = [];
  let list = null;
  const flushPara = () => {
    if (para.length) out.push({ t: 'p', c: parseInline(para.join('\n')) });
    para = [];
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('```')) {
      flushPara();
      list = null;
      const body = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) body.push(lines[i++]);
      out.push({ t: 'code', text: body.join('\n') });
      continue;
    }
    if (isBlank(line)) { flushPara(); list = null; continue; }
    if (line === '---') { flushPara(); list = null; out.push({ t: 'hr' }); continue; }
    const heading = /^(#{1,3}) (.*)$/.exec(line);
    if (heading && trim(heading[2]) !== '') {
      flushPara();
      list = null;
      out.push({ t: 'h', level: heading[1].length, c: parseInline(trim(heading[2])) });
      continue;
    }
    const item = listItem(line);
    if (item) {
      flushPara();
      const c = parseInline(trim(item.text));
      if (!list || list.t !== item.kind) {
        list = { t: item.kind, items: [] };
        out.push(list);
      }
      list.items.push(item.kind === 'todo' ? { done: item.done, c } : c);
      continue;
    }
    list = null;
    para.push(line);
  }
  flushPara();
  return out;
}

// One pass over an inline run: where code spans and links start and end, so no scan ever repeats.
// skip[i] = index just past the code span or link that starts at i (0 = none); linkK[i] = the link's ']'.
function analyze(s) {
  const n = s.length;
  const skip = new Int32Array(n + 1);
  const linkK = new Int32Array(n + 1);
  const nextTick = new Int32Array(n + 2).fill(-1);
  const nextClose = new Int32Array(n + 2).fill(-1);
  const nextSpace = new Int32Array(n + 2).fill(-1);
  const nextNewline = new Int32Array(n + 2).fill(-1);
  const bal = new Int32Array(n + 1);
  for (let i = n - 1; i >= 0; i--) {
    const c = s[i];
    nextTick[i] = c === '`' ? i : nextTick[i + 1];
    nextClose[i] = c === ']' ? i : nextClose[i + 1];
    nextSpace[i] = isSpace(c) ? i : nextSpace[i + 1];
    nextNewline[i] = c === '\n' ? i : nextNewline[i + 1];
  }
  for (let i = 0; i < n; i++) bal[i + 1] = bal[i] + (s[i] === '(' ? 1 : s[i] === ')' ? -1 : 0);
  // unbalanced[p] = index of the first ')' at or after p that no '(' at or after p balances, or -1.
  const unbalanced = new Int32Array(n + 1).fill(-1);
  const firstAt = new Map();
  for (let p = n; p >= 0; p--) {
    const x = firstAt.get(bal[p] - 1);
    if (x !== undefined) unbalanced[p] = x - 1;
    firstAt.set(bal[p], p);
  }
  for (let i = 0; i < n; i++) {
    if (s[i] === '`') {
      const j = nextTick[i + 1];
      if (j > i + 1) skip[i] = j + 1;
    } else if (s[i] === '[') {
      const k = nextClose[i + 1];
      if (k < 0 || k === i + 1 || s[k + 1] !== '(') continue;
      const nl = nextNewline[i + 1];
      if (nl >= 0 && nl < k) continue;
      const p = k + 2;
      const j = unbalanced[p];
      const w = nextSpace[p];
      if (j < 0 || j === p || (w >= 0 && w < j)) continue;
      skip[i] = j + 1;
      linkK[i] = k;
    }
  }
  return { skip, linkK };
}

// Index of the closing marker after `from`, skipping code spans and links; -1 if none. A closer must
// follow a non-space character. While looking for "*", a "**" pair is skipped as a unit. The scan's
// steps do not depend on where it started, so the answer from every position is computed once.
function closers(s, skip, marker) {
  const n = s.length;
  const res = new Int32Array(n + 3).fill(-1);
  for (let j = n - 1; j >= 0; j--) {
    if (skip[j] > 0) { res[j] = res[skip[j]]; continue; }
    if (marker === '*' && s.startsWith('**', j)) { res[j] = res[j + 2]; continue; }
    res[j] = j > 0 && s.startsWith(marker, j) && !isSpace(s[j - 1]) ? j : res[j + 1];
  }
  return res;
}

function parseInline(s) {
  const out = [];
  let buf = '';
  const flush = () => {
    if (buf) out.push({ t: 'text', v: buf });
    buf = '';
  };
  const { skip, linkK } = analyze(s);
  const closing = {};
  const closeAt = (from, marker) => {
    closing[marker] ??= closers(s, skip, marker);
    // The opener itself is never the closer: continue from its own step.
    const next = skip[from] > 0 ? skip[from] : marker === '*' && s.startsWith('**', from) ? from + 2 : from + 1;
    return closing[marker][next];
  };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '`') {
      if (skip[i] > 0) { flush(); out.push({ t: 'code', v: s.slice(i + 1, skip[i] - 1) }); i = skip[i]; continue; }
    } else if (c === '[') {
      if (skip[i] > 0) {
        flush();
        out.push({ t: 'link', text: s.slice(i + 1, linkK[i]), url: s.slice(linkK[i] + 2, skip[i] - 1) });
        i = skip[i];
        continue;
      }
    } else if (c === '*') {
      const marker = s.startsWith('**', i) ? '**' : '*';
      const open = i + marker.length;
      if (open < s.length && !isSpace(s[open])) {
        const close = closeAt(open, marker);
        if (close > 0) {
          flush();
          out.push({ t: marker === '**' ? 'b' : 'i', c: parseInline(s.slice(open, close)) });
          i = close + marker.length;
          continue;
        }
      }
    }
    buf += c;
    i++;
  }
  flush();
  return out;
}
