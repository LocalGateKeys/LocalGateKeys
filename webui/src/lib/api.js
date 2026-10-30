// Bridge to Python: window.pywebview.api.<group>_<verb>(...) and "lgk" events.

import { t } from './i18n.svelte.js';

let ready = null;

function bridge() {
  if (window.pywebview?.api) return Promise.resolve(window.pywebview.api);
  if (!ready) {
    ready = new Promise((resolve) => {
      window.addEventListener('pywebviewready', () => {
        ready = null;
        resolve(window.pywebview.api);
      }, { once: true });
    });
  }
  return ready;
}

// Texts Python marked with ``error_log: true`` (they send the user to the error log). The wording is
// translated, so the page never guesses from the text: it asks whether Python flagged this very text.
const errorLogTexts = new Set();

/** Remember a message Python flagged as pointing at the error log. */
export function markErrorLog(text) {
  const value = String(text ?? '').trim();
  if (value) errorLogTexts.add(value);
}

/** Was this text (or a text containing one) flagged by Python as pointing at the error log? */
export function isErrorLogText(text) {
  const value = String(text ?? '');
  if (!value) return false;
  for (const flagged of errorLogTexts) if (value.includes(flagged)) return true;
  return false;
}

// Find flagged messages anywhere in a reply: {error: {message, error_log}}, {text, error_log}, ...
function collectErrorLog(node, depth = 0) {
  if (!node || typeof node !== 'object' || depth > 6) return;
  if (Array.isArray(node)) { for (const item of node) collectErrorLog(item, depth + 1); return; }
  if (node.error_log === true) {
    markErrorLog(node.message);
    markErrorLog(node.text);
  }
  for (const value of Object.values(node)) collectErrorLog(value, depth + 1);
}

/** Call a bridge method. Always resolves to {ok: true, ...} or {ok: false, error: {code, message}}. */
export async function call(method, ...args) {
  try {
    const api = await bridge();
    const fn = api?.[method];
    if (typeof fn !== 'function') {
      return { ok: false, error: { code: 'bridge', message: t('api.err.notAvailable') } };
    }
    const result = await fn(...args);
    collectErrorLog(result);
    return result ?? { ok: false, error: { code: 'bridge', message: t('api.err.noReply') } };
  } catch {
    return { ok: false, error: { code: 'bridge', message: t('api.err.noAnswer') } };
  }
}

/** Subscribe to one Python event by name; returns an unsubscribe function. */
export function on(name, handler) {
  const listener = (event) => {
    if (event.detail?.name === name) {
      const detail = event.detail.detail ?? {};
      collectErrorLog(detail);
      handler(detail);
    }
  };
  window.addEventListener('lgk', listener);
  return () => window.removeEventListener('lgk', listener);
}
