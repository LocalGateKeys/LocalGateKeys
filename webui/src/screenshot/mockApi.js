// A stand-in for the Python bridge (window.pywebview.api) that serves the demo vault, so the real
// Svelte screens render in a normal browser. Every reply has the shape src/localvault/api/bridge.py
// returns; calls this file does not model resolve to {ok: true} and are logged once to the console.
// Dev-only: used by screenshot.html, never by index.html or popup.html.
import {
  COLLECTIONS, EXPIRING, KIND_LABELS, LOGINS, OTHER_PROFILES, PROFILE, TYPED, TYPE_NAV, WORDS, ageSeconds,
} from './demoData.js';
import { flags, healthReport, overviewHealth, reminders, securityCenter, settingsPage, syncView } from './snapshots.js';

const NOW = () => Date.now() / 1000;
const ok = (fields = {}) => ({ ok: true, ...fields });
const fail = (code, message, extra = {}) => ({ ok: false, error: { code, message, ...extra } });
const clone = (value) => JSON.parse(JSON.stringify(value));

/** Send a Python event to the page, as the real host does. */
export function emit(name, detail = {}) {
  window.dispatchEvent(new CustomEvent('lgk', { detail: { name, detail } }));
}

// ------------------------------------------------------------------ TOTP (RFC 6238, SHA-1, 6 digits)
function base32(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of text.replace(/=+$/, '').toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, '0');
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return bytes;
}

async function totp(secret, period = 30) {
  const now = NOW();
  const counter = Math.floor(now / period);
  const remaining = period - Math.floor(now % period);
  let code;
  try {
    const key = await crypto.subtle.importKey('raw', base32(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const msg = new ArrayBuffer(8);
    new DataView(msg).setUint32(4, counter);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
    const offset = mac[mac.length - 1] & 15;
    const value = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
    code = String(value % 1e6).padStart(6, '0');
  } catch {
    // No WebCrypto (page not opened from localhost): a stable stand-in that still changes each period.
    let h = counter;
    for (const ch of secret) h = (h * 31 + ch.charCodeAt(0)) % 1e6;
    code = String(h).padStart(6, '0');
  }
  return { code: `${code.slice(0, 3)} ${code.slice(3)}`, remaining, period };
}

// ------------------------------------------------------------------ the vault
export function createMockApi({ unlocked = true, appearance = 'dark' } = {}) {
  const state = {
    unlocked,
    appearance,
    favorites: new Set([...LOGINS, ...TYPED].filter((i) => i.favorite).map((i) => i.id)),
    trashed: new Map(), // id -> deleted_at
    settings: clone(settingsPage),
    lockAt: NOW() + 300,
  };
  const all = () => [...LOGINS.map((l) => ({ ...l, kind: 'web', source: 'credential' })),
    ...TYPED.map((t) => ({ ...t, source: 'typed' }))].filter((i) => !state.trashed.has(i.id));
  const find = (ref) => all().find((i) => i.id === ref?.id);
  const refOf = (item) => ({ source: item.source, id: item.id, kind: item.kind });
  const flagOf = (id) => (flags.weak.includes(id) ? 'weak' : flags.reused.includes(id) ? 'reused' : null);
  const collectionName = (item) => COLLECTIONS.find((c) => c.id === item.collection)?.name;

  function ageText(seconds) {
    const plural = (n, unit) => `${n} ${unit}${n === 1 ? '' : 's'}`;
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${plural(Math.floor(seconds / 60), 'minute')} ago`;
    if (seconds < 86400) return `${plural(Math.floor(seconds / 3600), 'hour')} ago`;
    return `${plural(Math.floor(seconds / 86400), 'day')} ago`;
  }

  function row(item) {
    return {
      ref: refOf(item),
      title: item.title,
      username: item.source === 'credential' ? item.username : '',
      kind_label: KIND_LABELS[item.kind] ?? item.kind,
      flag: flagOf(item.id),
      target: item.source === 'credential' ? item.origin : item.target,
      favorite: state.favorites.has(item.id),
      origin: item.source === 'credential' ? item.origin : null,
      icon: null,
    };
  }

  function vaultState() {
    const base = {
      choose_profile: false,
      state: state.unlocked ? 'unlocked' : 'locked',
      profile: { ...PROFILE },
      vault_exists: true,
      autolock_seconds: 300,
      status: '',
      appearance: state.appearance,
    };
    if (state.unlocked) return base;
    const chips = [PROFILE, ...OTHER_PROFILES].map((p) => ({ id: p.id, name: p.name, initial: p.name[0], active: p.id === PROFILE.id }));
    return { ...base, hello: true, camera: false, hello_auto: false, chips, subtitle: 'Locked 12 minutes ago',
      recovery_phrase: true, backoff: 0, backoff_message: '', master_required: false };
  }

  function matches(item, token, chip, query) {
    if (token === 'favorite' && !state.favorites.has(item.id)) return false;
    if (token?.startsWith('collection:') && item.collection !== token.slice(11)) return false;
    if (token && token !== 'favorite' && token !== 'recent' && !token.includes(':') && item.kind !== token) return false;
    if (chip === 'attention' && !flags.attention.includes(item.id)) return false;
    if (chip === 'no2fa' && !flags.no_2fa.includes(item.id)) return false;
    if (chip === 'expiring' && !EXPIRING.includes(item.id)) return false;
    if (query) {
      const q = query.toLowerCase();
      const hay = [item.title, item.username, item.origin, item.target, ...(item.tags ?? [])].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  const CONTEXT = {
    all: 'Everything safe to browse in this profile.',
    favorite: 'Items you marked as favorites in this profile.',
    recent: 'The items you changed most recently.',
    web: 'Browser logins within All items.',
    collection: 'Items in this collection.',
  };

  function locked() { return fail('locked', 'Unlock this profile first.'); }

  const handlers = {
    // ---- app, window, profiles
    app_info: () => ok({ version: '0.4.5', glass: false }),
    window_theme_sync: () => ok(),
    phone_backup_choose: () => ok({ handle: 'demo', name: 'LocalGateKeys-Backup-2026-10-20.lgkm', platform: 'android', created: '2026-10-20' }),
    phone_backup_preview: () => ok({ token: 'demo-token', lines: ['3 new items', '1 items updated from the backup', '2 already up to date', '1 items moved to the trash (deleted on the phone)'], status: 'Preview is ready. Review it, then restore.' }),
    phone_backup_commit: () => ok({ lines: ['3 new items', '1 items updated from the backup', '1 items moved to the trash (deleted on the phone)'], status: 'Phone backup restored.', changed: true }),
    phone_backup_cancel: () => ok(),
    vault_state: () => ok(vaultState()),
    vault_unlock: (password) => {
      if (!password) return fail('invalid', 'Enter your master password.');
      state.unlocked = true;
      setTimeout(() => emit('vault.state', vaultState()), 0);
      return ok(vaultState());
    },
    vault_unlock_hello: () => handlers.vault_unlock('hello'),
    vault_lock: () => {
      state.unlocked = false;
      setTimeout(() => emit('vault.state', vaultState()), 0);
      return ok(vaultState());
    },
    lock_emergency: () => handlers.vault_lock(),
    profiles_list: () => ok({ profiles: [PROFILE, ...OTHER_PROFILES].map((p) => ({ ...p, vault_exists: true })) }),
    profiles_select: () => ok(vaultState()),
    profiles_create: (name) => ok({ profile: { id: 'p-new', name, color: '#8B5CF6' } }),
    modal_answer: () => ok({ accepted: true }),
    hello_offer: () => ok({ offer: false }),
    updates_reminder: () => ok({ due: false }),

    // ---- home
    nav_get: () => {
      const items = state.unlocked ? all() : [];
      const count = (kind) => items.filter((i) => i.kind === kind).length;
      return ok({
        groups: [
          { name: 'Vault', entries: [
            { label: 'All items', icon: 'nav.allItems', token: null, count: state.unlocked ? items.length : null, action: null },
            { label: 'Favorites', icon: 'nav.favorite', token: 'favorite', count: state.unlocked ? items.filter((i) => state.favorites.has(i.id)).length : null, action: null },
            { label: 'Recently used', icon: 'nav.allItems', token: 'recent', count: null, action: null },
          ] },
          ...(state.unlocked ? [
            { name: 'Types', entries: TYPE_NAV.filter(([kind]) => count(kind)).map(([kind, label, icon]) => (
              { label, icon, token: kind, count: count(kind), action: null })) },
            { name: 'Collections & views', entries: COLLECTIONS.map((c) => (
              { label: c.name, icon: 'nav.collections', token: `collection:${c.id}`, count: null, action: null })) },
          ] : []),
          { name: 'Tools', entries: [
            { label: 'Security center', icon: 'nav.securityRecovery', token: null, count: null, action: 'security_health_clicked' },
            { label: 'Reminders', icon: 'nav.reminders', token: null, count: null, action: 'reminders_clicked' },
            { label: 'Sync', icon: 'nav.devicesConnections', token: null, count: null, action: 'sync_clicked' },
            { label: 'Devices & connections', icon: 'nav.devicesConnections', token: null, count: null, action: 'connections_clicked' },
            { label: 'Licence', icon: 'nav.settings', token: null, count: null, action: 'licence_clicked' },
            { label: 'Import & export', icon: 'nav.tools', token: null, count: null, action: 'import_export_clicked' },
            { label: 'Activity', icon: 'nav.allItems', token: null, count: null, action: 'activity_clicked' },
            { label: 'Trash', icon: 'nav.trash', token: null, count: null, action: 'trash_clicked' },
          ] },
        ],
        settings: { label: 'Settings', action: 'settings_clicked' },
      });
    },
    items_list: (token = null, chip = null, query = '') => {
      if (!state.unlocked) {
        return ok({ items: [], count: 0, chips: { attention: 0, no2fa: 0, expiring: 0 },
          context: { title: 'All items', text: CONTEXT.all }, empty: { title: 'Vault locked', text: 'Unlock this profile to browse its items.', action: 'Unlock vault' } });
      }
      const items = all();
      const present = new Set(items.map((i) => i.id));
      const chips = { attention: flags.attention.filter((id) => present.has(id)).length,
        no2fa: flags.no_2fa.filter((id) => present.has(id)).length, expiring: EXPIRING.filter((id) => present.has(id)).length };
      const rows = items.filter((i) => matches(i, token, chip, (query ?? '').trim()))
        .sort((a, b) => (state.favorites.has(b.id) - state.favorites.has(a.id)) || a.title.localeCompare(b.title, undefined, { sensitivity: 'base' }))
        .map(row);
      const typeLabel = TYPE_NAV.find(([kind]) => kind === token)?.[1];
      const collection = token?.startsWith('collection:') ? COLLECTIONS.find((c) => `collection:${c.id}` === token)?.name : null;
      const title = token === null ? 'All items' : token === 'favorite' ? 'Favorites' : token === 'recent' ? 'Recently used'
        : collection ?? typeLabel ?? 'All types';
      const key = token === null ? 'all' : token.startsWith('collection:') ? 'collection' : token;
      const text = CONTEXT[key] ?? `${KIND_LABELS[token] ?? 'Item'} items within All items.`;
      const empty = rows.length ? null : (query || token || chip)
        ? { title: 'No matching items', text: 'Try another name, username or tag, or clear your filters.', action: 'Clear filters' }
        : { title: 'No items yet', text: 'Add a website login, desktop login, or typed item to get started.', action: 'New item' };
      return ok({ items: rows, count: rows.length, chips, context: { title, text }, empty });
    },
    quick_search: (query = '') => ok({ profile: PROFILE.name, rows: all()
      .filter((i) => matches(i, null, null, query))
      .sort((a, b) => (state.favorites.has(b.id) - state.favorites.has(a.id)) || a.title.localeCompare(b.title))
      .map((i) => ({ ref: refOf(i), title: (state.favorites.has(i.id) ? '★ ' : '') + i.title,
        subtitle: (i.source === 'credential' ? i.username : '') || KIND_LABELS[i.kind] })) }),
    overview_get: () => (state.unlocked ? ok({
      health: { ...overviewHealth },
      reminders: clone(reminders),
      backup: { last_at: NOW() - 3 * 3600, count: 14, warning: '', stale: false },
    }) : ok({ health: null, reminders: [], backup: null })),
    codes_list: async () => {
      if (!state.unlocked) return ok({ codes: [] });
      const logins = LOGINS.filter((l) => l.totp && !state.trashed.has(l.id))
        .sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: 'base' }));
      const codes = [];
      for (const login of logins) {
        const r = row({ ...login, kind: 'web', source: 'credential' });
        codes.push({ ref: r.ref, title: r.title, username: r.username, origin: r.origin, icon: null, ...(await totp(login.totp)) });
      }
      return ok({ codes });
    },
    status_get: () => {
      if (!state.unlocked) return ok({ autolock: 'Locked', clipboard: '', encrypted: 'Local · Encrypted', hint: 'Ctrl K search · Ctrl N new · Ctrl L lock · F1 all shortcuts' });
      // A countdown that restarts, as the idle timer does when the vault is used.
      if (state.lockAt <= NOW()) state.lockAt = NOW() + 300;
      const left = Math.max(0, Math.round(state.lockAt - NOW()));
      return ok({ autolock: `Auto-lock in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`, clipboard: '',
        encrypted: 'Local · Encrypted', hint: 'Ctrl K search · Ctrl N new · Ctrl L lock · F1 all shortcuts' });
    },

    // ---- items
    item_detail: (ref) => {
      const item = find(ref);
      if (!state.unlocked) return locked();
      if (!item) return fail('not_found', 'This item no longer exists.');
      const subtitle = [KIND_LABELS[item.kind], collectionName(item), `updated ${ageText(ageSeconds(item.age))}`].filter(Boolean).join(' · ');
      if (item.source === 'typed') {
        return ok({ kind: item.kind, title: item.title, subtitle, fields: item.fields.filter((f) => !f.protected && f.value !== null)
          .map((f) => [f.label, String(f.value)]), tags: item.tags ?? [], favorite: state.favorites.has(item.id) });
      }
      return ok({ kind: 'web', title: item.title, subtitle, username: item.username, has_password: true, has_totp: !!item.totp,
        strict: false, notes: item.notes ?? '', tags: item.tags ?? [], target: item.origin, origin: item.origin,
        favorite: state.favorites.has(item.id), actions: ['open_website', 'edit'] });
    },
    item_reveal: (ref) => ok({ password: find(ref)?.password ?? '', mask_after: 30 }),
    item_copy: (ref, field) => ok({ message: field === 'totp' ? '2FA code copied. Clipboard clears in 30 seconds.'
      : field === 'username' ? 'Username copied.' : 'Password copied. Clipboard clears in 30 seconds.' }),
    item_totp: async (ref) => {
      const item = find(ref);
      return item?.totp ? ok(await totp(item.totp)) : fail('invalid_totp', 'Invalid setup key');
    },
    item_favorite: (ref, value) => {
      if (value) state.favorites.add(ref.id); else state.favorites.delete(ref.id);
      setTimeout(() => emit('items.changed'), 0);
      return ok({ message: value ? 'Added to favorites.' : 'Removed from favorites.' });
    },
    item_trash: (ref) => {
      state.trashed.set(ref.id, NOW());
      setTimeout(() => emit('items.changed'), 0);
      return ok({ message: 'Moved to Recently deleted. Use Tools to restore it.', undo: { ids: [ref.id] } });
    },
    item_open_website: () => ok({ message: '' }),
    typed_detail: (ref) => {
      const item = find(ref);
      if (!item) return fail('not_found', 'This item no longer exists.');
      return ok({ kind: item.kind, title: item.title,
        subtitle: [KIND_LABELS[item.kind], `updated ${ageText(ageSeconds(item.age))}`].join(' · '),
        fields: clone(item.fields), tags: item.tags ?? [], favorite: state.favorites.has(item.id), revision: 3 });
    },
    typed_reveal: (ref, field) => ok({ value: find(ref)?.secrets?.[field] ?? '', mask_after: 30 }),
    typed_copy: (ref, field) => ok({ message: `${find(ref)?.fields.find((f) => f.name === field)?.label ?? 'Value'} copied. Clipboard clears in 30 seconds.` }),
    typed_open: (ref) => {
      const item = find(ref);
      if (!item) return fail('not_found', 'This item no longer exists.');
      const values = {};
      for (const f of item.fields) if (!f.protected) values[f.name] = f.value;
      const present = {};
      for (const f of item.fields) if (f.protected) present[f.name] = f.present;
      return ok({ kind: item.kind, title: item.title, tags: item.tags ?? [], favorite: state.favorites.has(item.id),
        collection_ids: item.collection ? [item.collection] : [], revision: 3, values, protected_present: present });
    },
    typed_schema: () => ok({ kinds: [
      { kind: 'note', label: 'Note', note: '', fields: [{ name: 'body', label: 'Note body', type: 'multiline', protected: false }] },
      { kind: 'card', label: 'Payment card', note: 'Card details are stored encrypted. Browser fill releases only approved fields and never the PIN.', fields: [
        { name: 'cardholder', label: 'Cardholder', type: 'text', protected: false },
        { name: 'number', label: 'Card number (Luhn-checked; brand is detected)', type: 'text', protected: true },
        { name: 'expiry', label: 'Expiry MM/YY', type: 'text', protected: false },
        { name: 'cvv', label: 'CVV', type: 'text', protected: true },
        { name: 'pin', label: 'PIN (desktop only; never filled into a browser)', type: 'text', protected: true },
        { name: 'notes', label: 'Notes', type: 'multiline', protected: false }] },
      { kind: 'identity', label: 'Identity', note: '', fields: ['address', 'city', 'country', 'email', 'name', 'phone', 'postal_code']
        .map((name) => ({ name, label: TYPED[1].fields.find((f) => f.name === name)?.label ?? name, type: 'text', protected: false })) },
      { kind: 'wifi', label: 'Wi-Fi network', note: 'The password is protected. Security type and hidden flag are plain metadata.', fields: [
        { name: 'ssid', label: 'Network name (SSID)', type: 'text', protected: false },
        { name: 'password', label: 'Password', type: 'text', protected: true },
        { name: 'security', label: 'Security type', type: 'select', protected: false, choices: ['none', 'wep', 'wpa', 'wpa2', 'wpa3'] },
        { name: 'hidden', label: 'Hidden network', type: 'checkbox', protected: false }] },
    ] }),
    catalog_status: () => ok({ needs_update: false }),

    // ---- login extras
    recovery_count: (ref) => {
      const count = find(ref)?.recovery ?? 0;
      return ok({ count, text: count ? `${count} saved code(s) hidden. Reveal to view or edit.` : 'No saved codes. Reveal to add some.' });
    },
    recovery_get: (ref) => ok({ codes: Array.from({ length: find(ref)?.recovery ?? 0 }, (_, i) => `demo-${String(i + 1).padStart(2, '0')}-code`) }),
    policy_get: () => ok({ policy: { fill: 'click', sign_in: 'inherit', require_master_password: false, save_prompts: true } }),
    fields_get: (ref) => ok({ fields: ref?.id === 'github' ? [{ index: 0, name: 'Organisation', value: 'example-org', hidden: false }] : [] }),
    history_list: () => ok({ rows: [{ index: 0, changed_at: Math.round(NOW() - 120 * 86400) }], revision: 3 }),

    // ---- editor
    login_open: (ref) => {
      const item = find(ref);
      if (!item) return fail('not_found', 'This item no longer exists.');
      return ok({ draft_id: `draft-${item.id}`, kind: 'web', is_new: false, label: item.title, label_hint: item.title,
        // An opened login keeps its stored password until changed: no draft password, so no strength line.
        urls: [{ url: item.origin, match: 'exact_origin' }], app_path: '', username: item.username, password_set: false,
        favorite: state.favorites.has(item.id), tags: item.tags ?? [], notes: item.notes ?? '', totp_configured: !!item.totp,
        totp_allowed: true, policy: { fill: 'click', sign_in: 'inherit', require_master_password: false, save_prompts: true },
        errors: [], strength: null, dirty: false });
    },
    login_new: () => ok({ draft_id: 'draft-new', kind: 'web', is_new: true, label: '', label_hint: 'Untitled login',
      urls: [{ url: '', match: 'exact_origin' }], app_path: '', username: '', password_set: true, favorite: false, tags: [],
      notes: '', totp_configured: false, totp_allowed: true, policy: { fill: 'click', sign_in: 'inherit', require_master_password: false, save_prompts: true },
      errors: [], strength: { segments: 4, label: 'Very strong', reuse_text: 'not used anywhere else' }, dirty: false }),
    login_close: () => ok(),

    // ---- generator
    generator_get: () => ok({ options: { ...state.generator } }),
    generator_generate: (options = {}) => {
      state.generator = { ...state.generator, ...options };
      const o = state.generator;
      const pick = (n) => crypto.getRandomValues(new Uint32Array(1))[0] % n;
      let value;
      let health;
      if (o.mode === 'passphrase') {
        value = Array.from({ length: o.words }, () => WORDS[pick(WORDS.length)]).join(o.separator || '-');
        const bits = Math.round(o.words * Math.log2(5017));
        health = `${o.words} randomly selected words · about ${bits} bits from the word list · Very strong, centuries to guess offline`;
      } else {
        let set = '';
        if (o.lowercase) set += 'abcdefghijkmnopqrstuvwxyz';
        if (o.uppercase) set += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        if (o.digits) set += '23456789';
        if (o.symbols) set += o.symbol_set || '!@#$%^&*()-_=+[]{}:,.?';
        if (!set) return fail('invalid', 'Choose at least one character set.');
        value = Array.from({ length: o.length }, () => set[pick(set.length)]).join('');
        const label = o.length >= 14 ? 'Very strong' : o.length >= 10 ? 'Strong' : 'Fair';
        const time = o.length >= 14 ? 'centuries' : o.length >= 10 ? 'years' : 'hours';
        health = `${label} · ${time} to guess offline · Local estimate, not a security guarantee`;
      }
      return ok({ value, health, options: { ...o } });
    },
    generator_copy: () => ok({ message: 'Generated password copied. Clipboard clears in 30 seconds.' }),
    generator_username: () => ok({ value: `${WORDS[3]}-${WORDS[17]}-${Math.floor(Math.random() * 90 + 10)}` }),

    // ---- palette
    palette_query: (query = '') => {
      const q = query.trim().toLowerCase();
      const commands = PALETTE.filter((c) => !q || c.title.toLowerCase().includes(q) || c.subtitle.toLowerCase().includes(q));
      const items = q ? all().filter((i) => matches(i, null, null, q)).slice(0, 12).map((i) => ({
        kind: 'item', title: i.title, subtitle: i.source === 'credential' ? i.username : KIND_LABELS[i.kind], group: 'Items', ref: refOf(i) })) : [];
      return ok({ rows: [...items, ...commands] });
    },
    palette_run: (id) => {
      if (id === 'lock-now') { handlers.vault_lock(); return ok({ done: 'Vault locked.' }); }
      return ok(NAVIGATE[id] ?? { navigate: id });
    },

    // ---- trash
    trash_list: () => ok({ retention_text: 'Deleted items stay encrypted in the trash for 30 days, then are removed for good.',
      rows: [...state.trashed].map(([id, at]) => {
        const item = [...LOGINS.map((l) => ({ ...l, source: 'credential', kind: 'web' })), ...TYPED.map((t) => ({ ...t, source: 'typed' }))].find((i) => i.id === id);
        return { id, source: item.source, title: item.title, kind_label: KIND_LABELS[item.kind], username: item.username ?? '', deleted_at: Math.round(at) };
      }) }),
    trash_restore: (ids = []) => {
      ids.forEach((id) => state.trashed.delete(id));
      setTimeout(() => emit('items.changed'), 0);
      return ok({ message: `Restored ${ids.length} item(s).`, failed: [] });
    },

    // ---- security, health
    security_center: () => ok(clone(securityCenter)),
    security_set: () => ok({ message: 'Settings saved.' }),
    health_report: (filter = null) => {
      const report = clone(healthReport);
      if (filter === 'exposed') report.rows = [];
      else if (filter) report.rows = report.rows.filter((r) => r.categories.includes(filter));
      return ok(report);
    },
    health_scan: () => fail('needs_setting', 'Strict offline mode is on. Turn it off in Privacy settings to run an explicit external check.',
      { fix: { section: 'privacy' } }),
    health_cancel: () => ok(),

    // ---- settings, licence
    settings_page: () => ok(clone(state.settings)),
    settings_set: (key, value) => {
      for (const section of state.settings.sections) for (const r of section.rows) if (r.key === key) r.value = value;
      if (key === 'appearance') { state.appearance = value; setTimeout(() => emit('appearance', { appearance: value }), 0); }
      setTimeout(() => emit('settings.changed', { key }), 0);
      return ok({ message: 'Settings saved.', value });
    },
    licence_view: () => ok({
      headline: 'LocalGateKeys Pro',
      details: ['Licensed to: Alex Morgan (alex.morgan@example.com)', 'Updates until: 2027-10-22'],
      can_remove: true, warning: false,
      pitch: 'LocalGateKeys Pro: unlimited items, device sync, two-factor codes and attachments — US$4.99 once, lifetime updates.',
      purchase_url: '', upgrade: { headline: 'The free plan holds up to 4 items.', body: '' }, pro: true,
    }),

    // ---- sync
    sync_view: () => ok(clone(syncView)),
    sync_refresh: () => ok(clone(syncView)),
    sync_now: () => {
      setTimeout(() => emit('sync.status', {}), 400);
      return ok({ ...clone(syncView), message: 'Synced.' });
    },
    sync_firewall_status: () => ok({ supported: false }),
  };

  state.generator = { mode: 'password', length: 20, lowercase: true, uppercase: true, digits: true, symbols: true,
    avoid_ambiguous: true, symbol_set: '!@#$%^&*()-_=+[]{}:,.?', exclude: '', min_digits: 1, min_symbols: 1, words: 6,
    separator: '-', capitalize: false, append_number: false };

  const logged = new Set();
  const fallback = (name) => async () => {
    if (!logged.has(name)) {
      logged.add(name);
      console.info(`[screenshot harness] ${name} is not modelled; answering {ok: true}.`);
    }
    return ok();
  };

  // A Proxy so every name is a function, as pywebview exposes every public bridge method.
  return new Proxy({}, {
    get(_target, name) {
      // Not "then": api.js resolves a promise with this object, which must not look like a thenable.
      if (typeof name !== 'string' || name === 'then') return undefined;
      const handler = handlers[name];
      if (!handler) return fallback(name);
      return async (...args) => handler(...args);
    },
  });
}

// Recorded from app/tools.palette_results (empty query, unlocked) and _NAVIGATE.
const PALETTE = [
  ['backup-now', 'Back up now', 'Save an encrypted backup'],
  ['backup-verify', 'Verify a backup', 'Check that a backup opens'],
  ['backup-restore', 'Restore from backup…', 'Bring items back from a backup'],
  ['recovery-kit', 'Write recovery kit', 'Print or save your recovery kit'],
  ['generate-password', 'Generate password', 'Create a strong password'],
  ['new-item', 'New item', 'Add a login, card, note or other item'],
  ['quick-access', 'Quick access', 'Open the quick access window'],
  ['lock-now', 'Lock now', 'Lock the vault'],
  ['emergency-lock', 'Emergency lock', 'Lock and clear sensitive state'],
  ['switch-profile', 'Switch profile', 'Open another vault profile'],
  ['change-master', 'Change master password', 'Choose a new master password'],
  ['security-center', 'Security center', 'Weak, reused and 2FA-missing items'],
].map(([command_id, title, subtitle]) => ({ kind: 'command', title, subtitle, group: 'Actions', command_id }));

const NAVIGATE = {
  'generate-password': { navigate: 'generator' }, 'new-item': { navigate: 'new-item' }, settings: { navigate: 'settings' },
  'security-center': { navigate: 'security' }, 'change-master': { navigate: 'master' },
  'backup-now': { navigate: 'recovery', initial: 'create' }, 'backup-verify': { navigate: 'recovery', initial: 'verify' },
  'backup-restore': { navigate: 'recovery', initial: 'restore' }, 'recovery-kit': { navigate: 'recovery', initial: 'kit' },
};
