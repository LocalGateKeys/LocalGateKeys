// Bridge to Python: window.pywebview.api.<group>_<verb>(...) and "lgk" events.

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

/** Call a bridge method. Always resolves to {ok: true, ...} or {ok: false, error: {code, message}}. */
export async function call(method, ...args) {
  try {
    const api = await bridge();
    const fn = api?.[method];
    if (typeof fn !== 'function') {
      return { ok: false, error: { code: 'bridge', message: 'This action is not available.' } };
    }
    const result = await fn(...args);
    return result ?? { ok: false, error: { code: 'bridge', message: 'No reply from LocalGateKeys.' } };
  } catch {
    return { ok: false, error: { code: 'bridge', message: 'LocalGateKeys did not answer. Try again.' } };
  }
}

/** Subscribe to one Python event by name; returns an unsubscribe function. */
export function on(name, handler) {
  const listener = (event) => {
    if (event.detail?.name === name) handler(event.detail.detail ?? {});
  };
  window.addEventListener('lgk', listener);
  return () => window.removeEventListener('lgk', listener);
}
