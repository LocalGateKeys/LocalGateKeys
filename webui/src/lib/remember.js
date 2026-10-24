// Small per-window conveniences (last Settings section, last health filter). Storage can be missing or
// blocked in the WebView, so every read and write is optional.
const PREFIX = 'lgk.remember.';

export function recall(key, fallback = null) {
  try {
    const value = window.localStorage.getItem(PREFIX + key);
    return value === null ? fallback : JSON.parse(value);
  } catch {
    return fallback;
  }
}

export function remember(key, value) {
  try {
    window.localStorage.setItem(PREFIX + key, JSON.stringify(value));
  } catch {
    // Not remembered; the page works the same.
  }
}
