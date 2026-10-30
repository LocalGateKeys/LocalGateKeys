import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import SyncPill from '../components/SyncPill.svelte';
import SyncStatusPage from '../components/SyncStatusPage.svelte';
import { fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const status = (colour, state, extra = {}) => ({ ok: true, state, colour, text: 'Synced 2 min ago · 2 devices', device_count: 2,
  this_device: { name: 'Desk PC', last_text: 'Last synced 14:02 (2 min ago)' }, last_synced_at: 1, pro: true,
  devices: [{ id: 'ph', name: "Alex's iPhone", route: 'Wi-Fi', last_text: 'Never', warnings: [], routes: ['wifi'] }], ...extra });

describe('Sync pill', () => {
  for (const [colour, state, word] of [['green', 'ok', 'up to date'], ['orange', 'warning', 'needs a look'], ['red', 'error', 'error']]) {
    it(`shows the ${colour} state`, async () => {
      fakeApi({ sync_status: vi.fn().mockResolvedValue(status(colour, state)) });
      const onopen = vi.fn();
      const { container } = render(SyncPill, { onopen });
      const pill = await screen.findByRole('button', { name: new RegExp(`Sync status: .*${word}`) });
      expect(container.querySelector(`.dot.${colour}`)).not.toBeNull();
      await fireEvent.click(pill);
      expect(onopen).toHaveBeenCalled();
    });
  }

  it('is hidden when sync is off', async () => {
    const api = fakeApi({ sync_status: vi.fn().mockResolvedValue({ ok: true, state: 'off', colour: 'grey', text: 'Sync is off', devices: [] }) });
    render(SyncPill, { onopen: vi.fn() });
    await waitFor(() => expect(api.sync_status).toHaveBeenCalled());
    expect(screen.queryByRole('button')).toBeNull();
  });
});

describe('Sync status sheet', () => {
  it('lists this device and each peer, and syncs now', async () => {
    const api = fakeApi({ sync_status: vi.fn().mockResolvedValue(status('orange', 'warning',
      { devices: [{ id: 'ph', name: "Alex's iPhone", route: 'Wi-Fi and Cloud folder', last_text: 'Never', warnings: ['Not seen in 30 days'] }] })),
      sync_now: vi.fn().mockResolvedValue({ ok: true }) });
    const onsettings = vi.fn();
    render(SyncStatusPage, { onclose: vi.fn(), onsettings });
    expect(await screen.findByText("Alex's iPhone")).toBeInTheDocument();
    expect(screen.getByText('Wi-Fi and Cloud folder · Never')).toBeInTheDocument();
    expect(screen.getByText('Not seen in 30 days')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Sync now' }));
    await waitFor(() => expect(api.sync_now).toHaveBeenCalled());
    await fireEvent.click(screen.getByRole('button', { name: 'Open sync settings' }));
    expect(onsettings).toHaveBeenCalled();
  });
});
