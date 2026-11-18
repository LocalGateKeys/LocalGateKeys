import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import EmergencyAccess from './EmergencyAccess.svelte';

const COLLUSION = 'Enough holders acting together can open your backup at once.';
const PLAN = { plan_id: 'p', k: 2, n: 3, wait_days: 7, holders: ['Anna', 'Ben', 'Chris'], folder: 'D:\\Shared',
  owner: 'Ilias', created: '2027-01-15', stale: false };

function install(api) {
  window.pywebview = { api };
  return api;
}

afterEach(() => {
  vi.restoreAllMocks();
  delete window.pywebview;
  document.querySelectorAll('.print-portal').forEach((n) => n.remove());
});

describe('emergency access, owner', () => {
  it('shows the collusion warning in the plan editor and makes a plan', async () => {
    const api = install({
      heir_plan_list: vi.fn().mockResolvedValue({ ok: true, plan: null, requests: [], pro: true, has_phrase: true,
        collusion: COLLUSION, limits: {}, backup_error: '' }),
      heir_plan_choose_folder: vi.fn().mockResolvedValue({ ok: true, folder: 'D:\\Shared' }),
      heir_plan_create: vi.fn().mockResolvedValue({ ok: true, handle: 'h1', plan: PLAN, message: 'made' }),
      heir_plan_sheet: vi.fn().mockResolvedValue({ ok: true, owner: 'Ilias', plan_id: 'p', k: 2, n: 3, wait_days: 7,
        created: '2027-01-15', pages: [{ holder: 'Anna', index: 1, package_id: 'a', qr_size: 3, qr_path: 'M0 0h1v1h-1z' }] }),
      heir_plan_done: vi.fn().mockResolvedValue({ ok: true }),
    });
    vi.spyOn(window, 'print').mockImplementation(() => {});
    render(EmergencyAccess, { mode: 'owner', onclose: () => {} });
    expect((await screen.findByTestId('heir-collusion')).textContent).toBe(COLLUSION);
    const inputs = screen.getAllByLabelText(/^Holder \d$/);
    expect(inputs).toHaveLength(3);
    for (const [i, name] of ['Anna', 'Ben', 'Chris'].entries()) await fireEvent.input(inputs[i], { target: { value: name } });
    await fireEvent.click(screen.getByText('Choose folder'));
    await fireEvent.input(screen.getByLabelText('Recovery phrase'), { target: { value: 'twenty four words' } });
    await fireEvent.click(screen.getByText('Make plan'));
    await waitFor(() => expect(api.heir_plan_create).toHaveBeenCalledTimes(1));
    expect(api.heir_plan_create).toHaveBeenCalledWith(2, ['Anna', 'Ben', 'Chris'], 7, 'D:\\Shared', '', 'twenty four words');
    await screen.findByTestId('heir-issued');
    await fireEvent.click(screen.getByText('Print sheets'));
    await waitFor(() => expect(document.querySelector('.sheet-portal')).not.toBeNull());
    expect(document.querySelector('.sheet-portal').textContent).toContain('Anna');
  });

  it('lists requests with Deny and Grant now; grant asks for the phrase', async () => {
    const request = { id: 'r1', holder: 'Ben', days_left: 5, granted: false, created: '2027-02-01' };
    const api = install({
      heir_plan_list: vi.fn().mockResolvedValue({ ok: true, plan: PLAN, requests: [request], pro: true,
        has_phrase: true, collusion: COLLUSION, limits: {}, backup_error: '' }),
      heir_plan_deny: vi.fn().mockResolvedValue({ ok: true, message: 'denied' }),
      heir_plan_grant: vi.fn().mockResolvedValue({ ok: true, message: 'granted' }),
    });
    render(EmergencyAccess, { mode: 'owner', onclose: () => {} });
    const row = await screen.findByTestId('heir-request');
    expect(row.textContent).toContain('Ben');
    expect(row.textContent).toContain('5');
    await fireEvent.click(screen.getByText('Deny'));
    await waitFor(() => expect(api.heir_plan_deny).toHaveBeenCalledWith('r1'));
    await fireEvent.click(screen.getAllByText('Grant now')[0]);
    await fireEvent.input(screen.getByLabelText('Your recovery phrase'), { target: { value: 'phrase words' } });
    await fireEvent.submit(screen.getByRole('form', { name: 'Grant now' }));
    await waitFor(() => expect(api.heir_plan_grant).toHaveBeenCalledWith('r1', 'phrase words'));
  });

  it('says to re-issue shards when the plan is stale', async () => {
    install({ heir_plan_list: vi.fn().mockResolvedValue({ ok: true, plan: { ...PLAN, stale: true }, requests: [],
      pro: true, has_phrase: true, collusion: COLLUSION, limits: {}, backup_error: '' }) });
    render(EmergencyAccess, { mode: 'owner', onclose: () => {} });
    expect((await screen.findByRole('alert')).textContent).toContain('re-issue the shards');
  });

  it('says when the emergency folder cannot be reached', async () => {
    install({ heir_plan_list: vi.fn().mockResolvedValue({ ok: true, plan: PLAN, requests: [], pro: true,
      has_phrase: true, collusion: COLLUSION, limits: {}, backup_error: '', folder_reachable: false }) });
    render(EmergencyAccess, { mode: 'owner', onclose: () => {} });
    expect((await screen.findByTestId('heir-folder-unreachable')).textContent).toContain('cannot be reached');
  });

  it('on a device that got the plan by sync: no backup button, and this device\'s folder can be chosen', async () => {
    const api = install({
      heir_plan_list: vi.fn().mockResolvedValue({ ok: true, plan: { ...PLAN, folder: '', home: false }, requests: [],
        pro: true, has_phrase: true, collusion: COLLUSION, limits: {}, backup_error: '' }),
      heir_plan_set_folder: vi.fn().mockResolvedValue({ ok: true, message: 'set', plan: PLAN }),
    });
    render(EmergencyAccess, { mode: 'owner', onclose: () => {} });
    expect((await screen.findByTestId('heir-not-home')).textContent).toContain('another of your devices');
    expect(screen.queryByText('Write a backup now')).toBeNull();
    await fireEvent.click(screen.getByText('Choose folder'));
    await waitFor(() => expect(api.heir_plan_set_folder).toHaveBeenCalledTimes(1));
  });
});

describe('emergency access, heir', () => {
  it('adds a pasted shard, asks for access and restores once ready', async () => {
    let state = { ok: true, shards: [], plan: null, folder: '', status: null };
    const api = install({
      heir_receive_view: vi.fn(async () => state),
      heir_shard_add_text: vi.fn(async () => {
        state = { ...state, shards: [{ index: 1, holder: 'Anna' }], plan: { owner: 'Ilias', k: 2, n: 3, wait_days: 7 } };
        return { ok: true, message: 'added' };
      }),
      heir_receive_folder: vi.fn(async () => {
        state = { ...state, folder: 'D:\\Shared', status: { state: 'none', days_left: 0, missing: 0 } };
        return { ok: true, folder: 'D:\\Shared' };
      }),
      heir_request_create: vi.fn(async () => {
        state = { ...state, status: { state: 'ready', days_left: 0, missing: 0, granted: true } };
        return { ok: true, message: 'sent' };
      }),
      heir_restore: vi.fn().mockResolvedValue({ ok: true, message: 'restored', restored: true }),
    });
    render(EmergencyAccess, { mode: 'heir', onclose: () => {} });
    await fireEvent.input(await screen.findByLabelText(/paste a scanned shard code/, { selector: 'textarea' }), { target: { value: 'lgkheir:abc' } });
    await fireEvent.click(screen.getByText('Add'));
    await waitFor(() => expect(api.heir_shard_add_text).toHaveBeenCalledWith('lgkheir:abc'));
    expect((await screen.findByTestId('heir-shard')).textContent).toContain('Anna');
    await fireEvent.click(screen.getByText('Choose folder'));
    expect((await screen.findByTestId('heir-state')).textContent).toContain('not asked');
    await fireEvent.click(screen.getByText('Ask for access'));
    await screen.findByText('Restore as a new profile', { selector: 'strong' });
    await fireEvent.input(screen.getByLabelText('New profile name'), { target: { value: 'Inherited' } });
    await fireEvent.input(screen.getByLabelText('New master password'), { target: { value: 'new pass 12345' } });
    await fireEvent.input(screen.getByLabelText('Confirm the new master password'), { target: { value: 'new pass 12345' } });
    await fireEvent.click(screen.getByText('Restore', { selector: 'button *, button' }));
    await waitFor(() => expect(api.heir_restore).toHaveBeenCalledWith('Inherited', 'new pass 12345', 'new pass 12345'));
  });
});
