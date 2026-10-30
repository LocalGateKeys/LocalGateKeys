// Webui translations: the English catalog is bundled; the bridge supplies the chosen language.
import en from '../../../src/localvault/assets/i18n/en.json';
import { call, on } from './api.js';

const BRIDGE_WAIT_MS = 2000;

let state = $state({ lang: 'en', messages: en });
let fallbackRules = new Intl.PluralRules('en');
let rules = fallbackRules;

export function lang() {
  return state.lang;
}

export function setMessages(code, messages) {
  try {
    rules = new Intl.PluralRules(code);
  } catch {
    rules = fallbackRules;
  }
  state = { lang: code, messages: messages ?? {} };
  if (typeof document !== 'undefined') document.documentElement.lang = code;
}

function fill(text, params) {
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (whole, name) => (name in params ? String(params[name]) : whole));
}

export function t(key, params) {
  const found = state.messages[key] ?? en[key];
  if (found === undefined) return key;
  if (typeof found === 'string') return fill(found, params);
  if (found && typeof found === 'object') {
    const n = params && typeof params.count === 'number' ? params.count : 0;
    const form = found[rules.select(n)] ?? found.other;
    return typeof form === 'string' ? fill(form, params) : key;
  }
  return key;
}

export function formatDate(date, opts) {
  return new Intl.DateTimeFormat(state.lang, opts).format(date);
}

export function formatNumber(n) {
  return new Intl.NumberFormat(state.lang).format(n);
}

/** Fetch the chosen language from Python; on any failure keep what is loaded (English by default). */
let requestSeq = 0;

export async function loadLocale() {
  const mine = ++requestSeq;
  const apply = (r) => {
    if (mine !== requestSeq) return; // a newer request supersedes this one
    if (r?.ok && r.messages && typeof r.lang === 'string') setMessages(r.lang, r.messages);
  };
  let timer;
  try {
    // Without a bridge (dev server, tests) call() would wait for pywebview forever: stop waiting,
    // but a bundle that arrives later is still applied.
    const pending = Promise.resolve(call('i18n_bundle'));
    let waited = false;
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => { waited = true; resolve(); }, BRIDGE_WAIT_MS);
    });
    pending.then((r) => { if (waited) apply(r); }, () => {});
    const r = await Promise.race([pending, timeout]);
    if (!waited) apply(r);
  } catch {
    // keep the current messages
  } finally {
    clearTimeout(timer);
  }
}

if (typeof window !== 'undefined') on('language_changed', () => loadLocale());
