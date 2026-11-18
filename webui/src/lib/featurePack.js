// Small pure helpers for the 2026-11-15 feature pack pages (access rules, history, clean up, privacy proof).

import { formatDate, t } from './i18n.svelte.js';

/** Unix seconds -> a medium date and short time in the UI language. */
export function whenSeconds(seconds) {
  return formatDate(new Date(Number(seconds) * 1000), { dateStyle: 'medium', timeStyle: 'short' });
}

/** History row label: a sync arrival reads "Arrived by sync {date}", anything else "Changed {date}". */
export function historyLabel(row) {
  const date = whenSeconds(row.created_at);
  return row.change_type === 'sync' ? t('history.fromSync', { date }) : t('history.changedOn', { date });
}

// Login fields the history diff names by their stored path; shown with the editor's own labels.
const HISTORY_FIELD_KEYS = {
  username: 'loginEditor.username', password: 'loginEditor.password', label: 'loginEditor.title',
  title: 'loginEditor.title', notes: 'loginEditor.notes', totp: 'loginEditor.twoFactor',
  origin: 'loginEditor.website', url: 'loginEditor.website', website: 'loginEditor.website',
};

/** A history field path ("username", "payload.card_number", "totp.secret") as a label the user reads. */
export function historyFieldLabel(path) {
  const parts = String(path ?? '').split('.').filter((part) => part && part !== 'payload' && part !== 'scope');
  const head = parts[0] ?? '';
  if (HISTORY_FIELD_KEYS[head]) return t(HISTORY_FIELD_KEYS[head]);
  const last = parts[parts.length - 1] ?? String(path ?? '');
  const words = last.replace(/[_-]+/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').trim().toLowerCase();
  return words ? words[0].toUpperCase() + words.slice(1) : String(path ?? '');
}

/** Map a history restore error to its text: the backend message wins, else the contract key for the code. */
export function historyError(error) {
  if (error?.message) return error.message;
  if (error?.code === 'not_restorable') return t('history.notRestorable');
  if (error?.code === 'invalid_on_this_device') return t('history.invalidHere');
  return t('toast.couldNotComplete');
}

export const HYGIENE_LABELS = {
  same_login: 'hygiene.sameLogin',
  same_account_other_password: 'hygiene.sameAccountOtherPassword',
  same_site: 'hygiene.sameSite',
  same_item: 'hygiene.sameItem',
  not_changed_2y: 'hygiene.notChanged',
  expired: 'hygiene.expired',
};

/** Duplicate groups can be merged; age and expiry groups cannot. */
export const MERGEABLE = new Set(['same_login', 'same_account_other_password', 'same_site', 'same_item']);

export function hygieneLabel(type) {
  return HYGIENE_LABELS[type] ? t(HYGIENE_LABELS[type]) : type;
}

export const refKey = (ref) => `${ref?.source}:${ref?.id}`;

/** Merge pair for a group: the chosen keeper (default the first, newest item) and the first other item. */
export function mergePair(items, keeperKey = null) {
  if (!items || items.length < 2) return null;
  const keeper = items.find((i) => refKey(i.ref) === keeperKey) ?? items[0];
  const other = items.find((i) => i !== keeper);
  return { keeper: keeper.ref, other: other.ref };
}

/** Privacy proof facts as label/value rows, in the contract order. */
export function privacyFacts(facts) {
  if (!facts) return [];
  const onOff = (v) => t(v ? 'privacy.on' : 'privacy.off');
  const sync = { off: 'privacy.syncOff', folder: 'privacy.syncFolder', wifi: 'privacy.syncWifi', both: 'privacy.syncBoth' };
  return [
    { label: t('privacy.factSync'), value: sync[facts.sync] ? t(sync[facts.sync]) : String(facts.sync ?? '') },
    { label: t('privacy.factDevices'), value: String(facts.devices ?? 0) },
    { label: t('privacy.factShares'), value: String(facts.shares ?? 0) },
    { label: t('privacy.factItems'), value: String(facts.items ?? 0) },
    { label: t('privacy.factBreach'), value: onOff(facts.breach_checks) },
    { label: t('privacy.factOffline'), value: onOff(facts.strict_offline) },
    { label: t('privacy.factUpdates'), value: onOff(facts.update_check) },
  ];
}
