import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import Home from './Home.svelte';
import { UNLOCKED, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

// Each route() target that opens a page, and the name that page carries.
const PAGES = [
  ['security', 'Security center'], ['health', 'Password health'], ['settings', 'Settings'], ['licence', 'Licence'],
  ['connections', 'Connections'], ['profiles', 'Profiles'], ['sync', 'Sync'], ['reminders', 'Reminders'],
  ['activity', 'Activity history'], ['shortcuts', 'Keyboard shortcuts'], ['collections', 'Collections'],
  ['onboarding', 'Set up LocalGateKeys'], ['desktop-bind', 'Desktop app login'], ['import', 'Import'], ['export', 'Export'],
  ['transfer', 'Encrypted transfer'], ['phone-backup', 'Restore phone backup'], ['recovery', 'Backup & restore'],
  ['hello', 'Unlocking'], ['trash', 'Recently deleted'], ['scan-qr', 'Scan QR code'], ['import-menu', 'Import and export page'],
];

function open(target) { window.dispatchEvent(new CustomEvent('lgk-route', { detail: { route: target } })); }
const pane = () => document.querySelector('.home > .pane');
const sidebar = () => screen.getByRole('navigation', { name: 'Vault' });

describe('sidebar pages open in the content pane', () => {
  beforeEach(() => { fakeApi({ settings_page: vi.fn().mockResolvedValue({ ok: true, saved_text: '', sections: [] }) }); });

  it.each(PAGES)('%s renders inside the pane with the sidebar still shown', async (target, name) => {
    render(Home, { vault: UNLOCKED });
    await screen.findByRole('option', { name: /Alpha/ });
    open(target);
    const page = await screen.findByRole(name === 'Import and export page' ? 'region' : 'dialog', { name });
    expect(pane().contains(page)).toBe(true);
    expect(sidebar()).toBeVisible();
    expect(document.querySelector('.home > .side').contains(sidebar())).toBe(true);
    expect(document.querySelector('.trash-host')).toBeNull();
  });

  it('highlights the sidebar entry while its page is open, and a filter closes it', async () => {
    render(Home, { vault: UNLOCKED });
    const trash = await screen.findByRole('button', { name: 'Trash' });
    await fireEvent.click(trash);
    await screen.findByRole('dialog', { name: 'Recently deleted' });
    expect(trash).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('button', { name: /All items/ })).not.toHaveAttribute('aria-current');
    await fireEvent.click(screen.getByRole('button', { name: /Favorites/ }));
    await waitFor(() => expect(pane()).toBeNull());
    expect(trash).not.toHaveAttribute('aria-current');
  });

  it('clicking another entry replaces the page instead of stacking', async () => {
    render(Home, { vault: UNLOCKED });
    await fireEvent.click(await screen.findByRole('button', { name: 'Trash' }));
    await screen.findByRole('dialog', { name: 'Recently deleted' });
    await fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
    await screen.findByRole('dialog', { name: 'Settings' });
    expect(screen.queryByRole('dialog', { name: 'Recently deleted', hidden: true })).toBeNull();
    expect(pane().querySelectorAll('.page-slot')).toHaveLength(1);
    await fireEvent.keyDown(document.body, { key: 'Escape' });
    await waitFor(() => expect(pane()).toBeNull()); // back to the list, not to Trash
  });

  it('Esc goes back one page; Ctrl+[ and Ctrl+] go back and forward', async () => {
    render(Home, { vault: UNLOCKED });
    await screen.findByRole('option', { name: /Alpha/ });
    open('security');
    await screen.findByRole('dialog', { name: 'Security center' });
    open('health'); // opened from the security page: stacks
    await screen.findByRole('dialog', { name: 'Password health' });
    await fireEvent.keyDown(document.body, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Password health' })).toBeNull());
    expect(screen.getByRole('dialog', { name: 'Security center' })).toBeVisible();
    await fireEvent.keyDown(document.body, { key: ']', ctrlKey: true });
    expect(await screen.findByRole('dialog', { name: 'Password health' })).toBeInTheDocument();
    await fireEvent.keyDown(document.body, { key: '[', ctrlKey: true });
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Password health' })).toBeNull());
    await fireEvent.keyDown(document.body, { key: 'Escape' });
    await waitFor(() => expect(pane()).toBeNull());
    expect(screen.getByRole('option', { name: /Alpha/ })).toBeVisible();
  });
});
