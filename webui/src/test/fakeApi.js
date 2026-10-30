import { vi } from 'vitest';

export const PROFILE = { id: 'p1', name: 'Alex', color: '#2b6fe0' };
export const LOCKED = { ok: true, state: 'locked', profile: PROFILE, vault_exists: true, autolock_seconds: 300 };
export const UNLOCKED = { ...LOCKED, state: 'unlocked' };

export const ALPHA = {
  ref: { source: 'credential', id: 'a1', kind: 'web' }, title: 'Alpha', username: 'ann', kind_label: 'Website login',
  flag: 'weak', target: 'https://alpha.test', favorite: false, origin: 'https://alpha.test', icon: null,
};
export const NOTE = {
  ref: { source: 'typed', id: 'n1', kind: 'note' }, title: 'Router', username: '', kind_label: 'Secure note',
  flag: null, target: '', favorite: true, origin: null, icon: null,
};

export function fakeApi(overrides = {}) {
  const api = {
    vault_state: vi.fn().mockResolvedValue(UNLOCKED),
    vault_lock: vi.fn().mockResolvedValue(LOCKED),
    nav_get: vi.fn().mockResolvedValue({
      ok: true,
      groups: [
        { name: 'Vault', entries: [{ label: 'All items', icon: 'nav.allItems', token: null, count: 2, action: null },
          { label: 'Favorites', icon: 'nav.favorite', token: 'favorite', count: 1, action: null }] },
        { name: 'Types', entries: [{ label: 'Logins', icon: 'row.websiteGlobe', token: 'web', count: 1, action: null }] },
        { name: 'Tools', entries: [{ label: 'Trash', icon: 'nav.trash', token: null, count: null, action: 'trash_clicked' }] },
      ],
      settings: { label: 'Settings', action: 'settings_clicked' },
    }),
    items_list: vi.fn().mockResolvedValue({
      ok: true, items: [ALPHA, NOTE], count: 2, chips: { attention: 1, no2fa: 1, expiring: 0 },
      context: { title: 'All items', text: 'Everything safe to browse in this profile.' }, empty: null,
    }),
    import_card_dismiss: vi.fn().mockResolvedValue({ ok: true, import_card: false }),
    items_sort_set: vi.fn().mockResolvedValue({ ok: true, option: 'title_desc', favorites_first: true, options: [] }),
    overview_get: vi.fn().mockResolvedValue({
      ok: true, health: { score: 50, label: 'Fair', weak: 1, reused: 0, no_2fa: 1 }, reminders: [],
      backup: { last_at: null, count: 0, warning: '', stale: true },
    }),
    codes_list: vi.fn().mockResolvedValue({ ok: true, codes: [] }),
    status_get: vi.fn().mockResolvedValue({ ok: true, autolock: 'Auto-lock in 4:59', clipboard: '', encrypted: 'Local · Encrypted', hint: 'Ctrl K search' }),
    item_detail: vi.fn().mockResolvedValue({
      ok: true, kind: 'web', title: 'Alpha', subtitle: 'Website login · updated just now', username: 'ann',
      has_password: true, has_totp: true, strict: false, notes: 'alpha notes', tags: ['work'],
      target: 'https://alpha.test', origin: 'https://alpha.test', favorite: false, actions: ['open_website', 'edit'],
    }),
    item_reveal: vi.fn().mockResolvedValue({ ok: true, password: 'pw-alpha-1234567', mask_after: 30 }),
    item_copy: vi.fn().mockResolvedValue({ ok: true, message: 'Password copied. Clipboard clears in 30 seconds.' }),
    item_totp: vi.fn().mockResolvedValue({ ok: true, code: '123 456', remaining: 19, period: 30 }),
    item_favorite: vi.fn().mockResolvedValue({ ok: true, message: 'Added to favorites.' }),
    item_trash: vi.fn().mockResolvedValue({ ok: true, message: 'Moved to Recently deleted. Use Tools to restore it.' }),
    item_open_website: vi.fn().mockResolvedValue({ ok: true, message: '' }),
    login_new: vi.fn().mockResolvedValue({
      ok: true, draft_id: 'd1', kind: 'web', is_new: true, label: '', label_hint: 'Untitled login',
      urls: [{ url: '', match: 'exact_origin' }], username: '', password_set: true, favorite: false, tags: [],
      notes: '', totp_configured: false, policy: {}, errors: [], strength: { segments: 4, label: 'Very strong', reuse_text: 'not used anywhere else' }, dirty: false,
    }),
    login_open: vi.fn(),
    login_update: vi.fn(async (id, changes) => ({ ok: true, draft_id: id, kind: 'web', is_new: true, label: '', label_hint: 'alpha.test',
      urls: changes.urls ?? [{ url: '', match: 'exact_origin' }], username: changes.username ?? '', password_set: true,
      favorite: false, tags: [], notes: '', totp_configured: false, policy: {}, errors: [], strength: null, dirty: true })),
    login_regenerate: vi.fn(),
    login_save: vi.fn().mockResolvedValue({ ok: true, ref: { source: 'credential', id: 'a2', kind: 'web' } }),
    login_close: vi.fn().mockResolvedValue({ ok: true }),
    generator_get: vi.fn().mockResolvedValue({ ok: true, options: { mode: 'password', length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, words: 6, separator: 'dash' } }),
    generator_generate: vi.fn().mockResolvedValue({ ok: true, value: 'k7#Rv-pQ2m!Xe9wAbCd', health: 'Very strong · centuries to guess offline · Local estimate, not a security guarantee', options: {} }),
    generator_copy: vi.fn().mockResolvedValue({ ok: true, message: 'Generated password copied. Clipboard clears in 30 seconds.' }),
    generator_username: vi.fn(),
    palette_query: vi.fn().mockResolvedValue({ ok: true, rows: [
      { kind: 'command', title: 'Lock now', subtitle: 'Lock this profile', group: 'Actions', command_id: 'lock-now' },
      { kind: 'item', title: 'Alpha', subtitle: 'ann', group: 'Items', ref: ALPHA.ref },
    ] }),
    palette_run: vi.fn().mockResolvedValue({ ok: true, done: 'Vault locked.' }),
    typed_schema: vi.fn().mockResolvedValue({ ok: true, kinds: [
      { kind: 'note', label: 'Note', note: '', fields: [{ name: 'body', label: 'Note body', type: 'multiline', protected: false }] },
      { kind: 'card', label: 'Payment card', note: 'Card details are stored encrypted.', fields: [
        { name: 'cardholder', label: 'Cardholder', type: 'text', protected: false },
        { name: 'number', label: 'Card number (Luhn-checked; brand is detected)', type: 'text', protected: true },
        { name: 'notes', label: 'Notes', type: 'multiline', protected: false }] },
      { kind: 'document', label: 'Document', note: 'Maximum file size: 25 MiB', fields: [{ name: 'description', label: 'Description', type: 'text', protected: false }] },
    ] }),
    typed_detail: vi.fn().mockResolvedValue({ ok: true, kind: 'card', title: 'Visa', subtitle: 'Payment card', favorite: false, tags: [], revision: 3,
      fields: [{ name: 'cardholder', label: 'Cardholder', value: 'Ann', protected: false, present: true },
        { name: 'number', label: 'Card number (Luhn-checked; brand is detected)', value: null, protected: true, present: true }] }),
    typed_open: vi.fn().mockResolvedValue({ ok: true, kind: 'card', title: 'Visa', tags: [], favorite: false, collection_ids: [], revision: 3,
      values: { cardholder: 'Ann' }, protected_present: { number: true } }),
    typed_save: vi.fn().mockResolvedValue({ ok: true, ref: { source: 'typed', id: 'c1', kind: 'card' } }),
    typed_reveal: vi.fn().mockResolvedValue({ ok: true, value: '4111111111111111', mask_after: 30 }),
    typed_copy: vi.fn().mockResolvedValue({ ok: true, message: 'Number copied. Clipboard clears in 30 seconds.' }),
    doc_create: vi.fn().mockResolvedValue({ ok: true, ref: { source: 'typed', id: 'd1', kind: 'document' } }),
    doc_preview: vi.fn().mockResolvedValue({ ok: true, kind: 'text', content: 'hello', truncated: false }),
    doc_open: vi.fn().mockResolvedValue({ ok: true, message: 'Opened a.txt.' }),
    doc_save_copy: vi.fn().mockResolvedValue({ ok: true, message: 'Copy saved' }),
    doc_replace: vi.fn().mockResolvedValue({ ok: true }),
    trash_list: vi.fn().mockResolvedValue({ ok: true, retention_text: 'Entries stay encrypted for 30 days.',
      rows: [{ id: 't1', source: 'typed', title: 'Router', kind_label: 'Note', username: '', deleted_at: 1700000000 },
        { id: 'l1', source: 'credential', title: 'Alpha', kind_label: 'Login', username: 'ann', deleted_at: 1700000100 }] }),
    trash_restore: vi.fn().mockResolvedValue({ ok: true, message: 'Restored 1 item(s).', failed: [] }),
    trash_purge: vi.fn().mockResolvedValue({ ok: true, message: 'Permanently deleted 1 item(s).' }),
    trash_empty: vi.fn().mockResolvedValue({ ok: true, message: 'Permanently deleted 2 item(s).' }),
    history_list: vi.fn().mockResolvedValue({ ok: true, rows: [{ index: 0, changed_at: 1700000000 }], revision: 1 }),
    history_copy: vi.fn().mockResolvedValue({ ok: true, message: 'Previous password copied.' }),
    recovery_count: vi.fn().mockResolvedValue({ ok: true, count: 2, text: '2 saved code(s) hidden. Reveal to view or edit.' }),
    recovery_get: vi.fn().mockResolvedValue({ ok: true, codes: ['code-1', 'code-2'] }),
    recovery_save: vi.fn().mockResolvedValue({ ok: true, message: 'Recovery codes saved.' }),
    recovery_use_next: vi.fn().mockResolvedValue({ ok: true, message: 'Recovery code copied and removed from the list.' }),
    fields_get: vi.fn().mockResolvedValue({ ok: true, fields: [{ index: 0, name: 'PIN', value: null, hidden: true }] }),
    fields_save: vi.fn().mockResolvedValue({ ok: true, message: 'Custom fields saved.' }),
    policy_get: vi.fn().mockResolvedValue({ ok: true, policy: { fill: 'click', sign_in: 'inherit', require_master_password: false, save_prompts: true } }),
    policy_save: vi.fn().mockResolvedValue({ ok: true, message: 'Access policy saved. It applies from the next fill.' }),
    ga_parse: vi.fn().mockResolvedValue({ ok: true, token: 'g1', accounts: [{ index: 0, issuer: 'Alpha', label: 'ann' }], skipped: [], best: 0, batch: { index: 0, size: 1 } }),
    ga_apply: vi.fn().mockResolvedValue({ ok: true, draft_id: 'd1', kind: 'web', is_new: true, label: '', label_hint: 'x', urls: [], username: '',
      password_set: true, favorite: false, tags: [], notes: '', totp_configured: true, policy: {}, errors: [], strength: null, dirty: true }),
    modal_answer: vi.fn().mockResolvedValue({ ok: true, accepted: true }),
    ...overrides,
  };
  window.pywebview = { api };
  return api;
}

export function emit(name, detail) {
  window.dispatchEvent(new CustomEvent('lgk', { detail: { name, detail } }));
}
