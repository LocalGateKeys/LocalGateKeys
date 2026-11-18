import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import AccessRules from '../components/AccessRules.svelte';
import AutoTypeSection from '../components/AutoTypeSection.svelte';
import HygienePage from '../components/HygienePage.svelte';
import ItemHistorySheet from '../components/ItemHistorySheet.svelte';
import PrivacyProofPage from '../components/PrivacyProofPage.svelte';
import TravelSection from '../components/TravelSection.svelte';
import { historyError, historyFieldLabel, historyLabel, hygieneLabel, mergePair, privacyFacts } from '../lib/featurePack.js';
import { ALPHA, fakeApi } from '../test/fakeApi.js';

afterEach(() => cleanup());

const ACCESS = { ok: true, access: { copy: 'normal', phones: 'full', expires: '' }, reauth: false, never_fill: false,
  unknown: false, expired: false, pro: true };

describe('feature pack helpers', () => {
  it('labels history rows by change type', () => {
    expect(historyLabel({ created_at: 1700000000, change_type: 'sync' })).toMatch(/^Arrived by sync /);
    expect(historyLabel({ created_at: 1700000000, change_type: 'update' })).toMatch(/^Changed /);
  });
  it('names history fields with labels, never raw paths (live check 2026-11-15)', () => {
    expect(historyFieldLabel('username')).toBe('Username');
    expect(historyFieldLabel('password')).toBe('Password');
    expect(historyFieldLabel('totp.secret')).toBe('Two-factor');
    expect(historyFieldLabel('payload.card_number')).toBe('Card number');
  });
  it('maps restore errors to their text', () => {
    expect(historyError({ code: 'not_restorable' })).toBe("This field can't be restored.");
    expect(historyError({ code: 'invalid_on_this_device' })).toBe("This version can't be restored on this device.");
    expect(historyError({ code: 'x', message: 'From backend' })).toBe('From backend');
  });
  it('labels hygiene groups and picks the merge pair', () => {
    expect(hygieneLabel('same_login')).toBe('Same login saved more than once');
    const a = { ref: { source: 'credential', id: 'a' } };
    const b = { ref: { source: 'credential', id: 'b' } };
    expect(mergePair([a, b])).toEqual({ keeper: a.ref, other: b.ref });
    expect(mergePair([a, b], 'credential:b')).toEqual({ keeper: b.ref, other: a.ref });
    expect(mergePair([a])).toBeNull();
  });
  it('turns privacy facts into rows', () => {
    const rows = privacyFacts({ sync: 'both', devices: 2, shares: 0, items: 5, breach_checks: false, strict_offline: true, update_check: true });
    expect(rows[0]).toEqual({ label: 'Sync', value: 'Folder and Wi-Fi' });
    expect(rows.find((r) => r.label === 'Breach checks').value).toBe('Off');
    expect(rows.find((r) => r.label === 'Strict offline').value).toBe('On');
  });
});

describe('AccessRules', () => {
  it('saves a switch and puts it back when refused', async () => {
    const save = vi.fn()
      .mockResolvedValueOnce({ ...ACCESS, reauth: true, message: 'Access rules saved.' })
      .mockResolvedValueOnce({ ok: false, error: { code: 'pro_required', message: 'Access rules are part of Pro.' } });
    fakeApi({ access_get: vi.fn().mockResolvedValue(ACCESS), access_save: save });
    render(AccessRules, { selected: ALPHA.ref });
    const reauth = await screen.findByRole('switch', { name: "Confirm it's you every time" });
    await fireEvent.click(reauth);
    expect(save).toHaveBeenCalledWith(ALPHA.ref, { reauth: true });
    const copyOnce = screen.getByRole('switch', { name: 'Copy once, then confirm again' });
    await fireEvent.click(copyOnce);
    await waitFor(() => expect(save).toHaveBeenLastCalledWith(ALPHA.ref, { copy: 'once' }));
    await waitFor(() => expect(copyOnce.checked).toBe(false));
    expect(screen.getByText(/older LocalGateKeys/)).toBeTruthy();
  });
});

describe('ItemHistorySheet', () => {
  it('shows a diff, reveals protected values and restores one field', async () => {
    const diff = vi.fn()
      .mockResolvedValueOnce({ ok: true, fields: [{ field: 'password', before: '[protected]', after: '[protected]', secret: true, restorable: true }] })
      .mockResolvedValue({ ok: true, fields: [{ field: 'password', before: 'old', after: 'new', secret: true, restorable: true }] });
    const restore = vi.fn().mockResolvedValue({ ok: true, message: 'password restored.' });
    const restored = vi.fn();
    fakeApi({
      item_history_list: vi.fn().mockResolvedValue({ ok: true, pro: false, rows: [{ snapshot_id: 's1', created_at: 1700000000, change_type: 'update' }] }),
      item_history_diff: diff, item_history_restore_field: restore,
    });
    render(ItemHistorySheet, { selected: ALPHA.ref, onclose: () => {}, onrestored: restored });
    expect(await screen.findByText(/Free keeps 5 versions/)).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: /^Changed / }));
    expect(await screen.findAllByText('Hidden. Show to compare.')).toHaveLength(2);
    await fireEvent.click(screen.getByRole('button', { name: 'Show' }));
    await waitFor(() => expect(diff).toHaveBeenLastCalledWith(ALPHA.ref, 's1', true));
    expect(await screen.findByText('old')).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Restore this field' }));
    expect(screen.getByText('Restore Password from this version?')).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Restore this field' }));
    await waitFor(() => expect(restore).toHaveBeenCalledWith(ALPHA.ref, 's1', 'password'));
    expect(restored).toHaveBeenCalled();
  });
  it('says when there is no history yet', async () => {
    fakeApi({ item_history_list: vi.fn().mockResolvedValue({ ok: true, pro: true, rows: [] }) });
    render(ItemHistorySheet, { selected: ALPHA.ref, onclose: () => {} });
    expect(await screen.findByText('No earlier versions on this device yet.')).toBeTruthy();
    expect(screen.queryByText(/Free keeps/)).toBeNull();
  });
});

describe('HygienePage', () => {
  const ITEMS = [
    { ref: { source: 'credential', id: 'a', kind: 'web' }, title: 'Alpha new', subtitle: 'ann', updated_at: 1700000000 },
    { ref: { source: 'credential', id: 'b', kind: 'web' }, title: 'Alpha old', subtitle: 'ann', updated_at: 1600000000 },
  ];
  it('reviews a merge with the newest item kept, and disables bulk actions on Free', async () => {
    const preview = vi.fn().mockResolvedValue({ ok: true, fields: [{ field: 'notes', before: '', after: 'merged', secret: false }] });
    const merge = vi.fn().mockResolvedValue({ ok: true, message: 'Merged.' });
    fakeApi({
      hygiene_scan: vi.fn().mockResolvedValue({ ok: true, pro: false, can_undo: false, summary: { dupes: 1, old: 0, expired: 0 },
        groups: [{ type: 'same_login', items: ITEMS }] }),
      hygiene_merge_preview: preview, hygiene_merge: merge,
    });
    render(HygienePage, { onclose: () => {}, onopen: () => {} });
    expect(await screen.findByText('1 duplicates, 0 not changed in 2 years, 0 expired')).toBeTruthy();
    expect(screen.getByText('Cleaning up many items at once is part of Pro.')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Merge all same logins' }).disabled).toBe(true);
    await fireEvent.click(screen.getByRole('button', { name: 'Merge' }));
    await waitFor(() => expect(preview).toHaveBeenCalledWith(ITEMS[0].ref, ITEMS[1].ref));
    expect(await screen.findByText('merged')).toBeTruthy();
    const merges = screen.getAllByRole('button', { name: 'Merge' });
    await fireEvent.click(merges[merges.length - 1]);
    await waitFor(() => expect(merge).toHaveBeenCalledWith(ITEMS[0].ref, ITEMS[1].ref));
  });
});

describe('PrivacyProofPage', () => {
  it('shows facts, claims, connections and the export hint', async () => {
    const exp = vi.fn().mockResolvedValue({ ok: true, path: 'C:/x.json', file_name: 'proof.json', signed: false, fingerprint: null });
    fakeApi({
      privacy_proof_get: vi.fn().mockResolvedValue({ ok: true, signed: false, fingerprint: null, since: null,
        claims: [{ id: 'connections_listed', text: 'Every connection is listed.' }],
        document: { facts: { sync: 'off', devices: 0, shares: 0, items: 3, breach_checks: false, strict_offline: false, update_check: true },
          network: { available: true, entries: [{ purpose: 'update_check', host: 'example.invalid', result: 'ok', at: '2026-11-15T10:00:00Z' }],
            counts: { website_icon: 14 } } } }),
      privacy_proof_export: exp,
    });
    render(PrivacyProofPage, { onclose: () => {} });
    expect(await screen.findByText('Every connection is listed.')).toBeTruthy();
    expect(screen.getByText('example.invalid')).toBeTruthy();
    expect(screen.getByText(/14 connections for/)).toBeTruthy();
    expect(screen.getByText('Not signed: sync is off on this device.')).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Export proof' }));
    expect(await screen.findByText('Check it on a PC: lgk proof verify "proof.json"')).toBeTruthy();
  });
});

describe('Settings sections', () => {
  it('hides travel mode while the duress vault is open', async () => {
    const get = vi.fn().mockResolvedValue({ ok: true, on: false, collections: [], tags: [], hidden_count: 0,
      available_collections: [], available_tags: ['work'], pro: true, duress: true });
    fakeApi({ travel_get: get });
    render(TravelSection);
    await waitFor(() => expect(get).toHaveBeenCalled());
    expect(screen.queryByText('Travel mode')).toBeNull();
  });
  it('saves chosen travel tags and shows the on state', async () => {
    const base = { ok: true, on: false, collections: [], tags: [], hidden_count: 0, available_collections: [{ id: 'c1', name: 'Work' }],
      available_tags: ['trip'], pro: true, duress: false };
    const save = vi.fn().mockResolvedValue({ ...base, on: true, tags: ['trip'], hidden_count: 4, message: 'Travel mode updated.' });
    fakeApi({ travel_get: vi.fn().mockResolvedValue(base), travel_save: save });
    render(TravelSection);
    await fireEvent.click(await screen.findByRole('checkbox', { name: 'trip' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(save).toHaveBeenCalledWith([], ['trip']));
    expect(await screen.findByText('Travel mode is on: 4 items hidden on this device.')).toBeTruthy();
  });
  it('auto-type confirm is disabled until auto-type is on', async () => {
    const set = vi.fn().mockResolvedValue({ ok: true, enabled: true, confirm: true });
    fakeApi({ autotype_settings_get: vi.fn().mockResolvedValue({ ok: true, enabled: false, confirm: true }), autotype_settings_set: set });
    render(AutoTypeSection);
    const confirm = await screen.findByRole('switch', { name: 'Ask before typing' });
    expect(confirm.disabled).toBe(true);
    await fireEvent.click(screen.getByRole('switch', { name: 'Allow typing into other windows' }));
    await waitFor(() => expect(set).toHaveBeenCalledWith(true, true));
    await waitFor(() => expect(confirm.disabled).toBe(false));
  });
});
