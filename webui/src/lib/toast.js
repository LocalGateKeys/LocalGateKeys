import { call, markErrorLog, isErrorLogText } from './api.js';
import { t } from './i18n.svelte.js';

/**
 * Does this text send the user to the error log? Python says so with an ``error_log: true`` flag on the
 * failure, notice or issue (the wording is translated, so the page never matches it). Such text gets an
 * "Open error log" button.
 */
export function mentionsErrorLog(text) {
  return isErrorLogText(text);
}

/** The "Open error log" button for a notice. */
export function errorLogAction() {
  return { id: 'errorlog', label: t('toast.openErrorLog'), run: async () => okOrToast(await call('errorlog_open'), t('home.errorLogNotOpened')) };
}

// Page-side notifications reuse the same "toast" event Python sends.
export function toast(title, message = '', kind = 'info', actions = []) {
  window.dispatchEvent(new CustomEvent('lgk', { detail: { name: 'toast', detail: { kind, title, message, actions } } }));
}

/** Open a page (e.g. a Settings section) the same way Python's "navigate" event does. */
export function openRoute(route, params = {}) {
  window.dispatchEvent(new CustomEvent('lgk-route', { detail: { route, params } }));
}

/** A {label, run} button from Python's {label, route, params} action. */
export function routeAction(action) {
  return { ...(action.id ? { id: action.id } : {}), label: action.label, run: () => openRoute(action.route, action.params ?? {}) };
}

/**
 * Toast a successful result's ``message`` with its buttons: ``undo`` ({ids} moved to Trash) becomes
 * "Undo", ``action`` (a route) becomes a link such as "Open Privacy settings".
 */
export function notice(result) {
  const actions = [];
  if (result?.undo?.ids?.length) {
    actions.push({ label: t('toast.undo'), primary: true, run: async () => {
      const restored = await call('trash_restore', result.undo.ids);
      if (okOrToast(restored, t('toast.notRestored'))) toast(restored.message);
    } });
  }
  if (result?.action) actions.push(routeAction(result.action));
  toast(result?.message ?? '', '', 'info', actions);
}

/**
 * Buttons for a failure caused by a setting (``error.fix``): turn it on and try again, and open its
 * Settings section. Empty when the error has no fix.
 */
export function fixActions(error, retry = null) {
  const fix = error?.fix;
  if (!fix) return [];
  const actions = [];
  if (fix.key) {
    actions.push({ label: fix.label ?? t('toast.turnOn'), primary: true, run: async () => {
      const result = await call('settings_set', fix.key, fix.value ?? true);
      if (okOrToast(result, t('toast.settingNotChanged')) && retry) retry();
    } });
  }
  actions.push({ label: t('toast.openSettings'), run: () => openRoute('settings', { section: fix.section }) });
  return actions;
}

/** Show a bridge failure (if any) and report whether the call succeeded. */
export function okOrToast(result, title = t('toast.couldNotComplete'), retry = null) {
  if (result?.ok) return true;
  const error = result?.error;
  if (error?.error_log === true) markErrorLog(error.message);
  if (error?.code !== 'cancelled') toast(title, error?.message ?? '', error?.fix ? 'info' : 'error', fixActions(error, retry));
  return false;
}
