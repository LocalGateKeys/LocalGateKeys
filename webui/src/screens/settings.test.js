import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import SettingsPage from '../components/SettingsPage.svelte';
import LicencePage from '../components/LicencePage.svelte';
import ProfilesPage from '../components/ProfilesPage.svelte';
import App from '../App.svelte';
import { LOCKED, emit, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; delete document.documentElement.dataset.theme; });

const PAGE = { ok: true, saved_text: 'Changes save as you make them', sections: [
  { key: 'locking', title: 'Locking', rows: [
    { type: 'choice', key: 'auto_lock_seconds', title: 'Lock after inactivity', description: 'When you have not used your computer or the vault',
      value: 300, options: [{ label: '5 minutes', value: 300 }, { label: '15 minutes', value: 900 }] },
    { type: 'switch', key: 'lock_on_sleep', title: 'Lock on sleep', description: '', value: true },
  ] },
  { key: 'appearance', title: 'Appearance & app', keywords: ['theme', 'dark'], rows: [
    { type: 'segmented', key: 'appearance', title: 'Theme', description: '', value: 'system',
      options: [{ label: 'System', value: 'system' }, { label: 'Light', value: 'light' }, { label: 'Dark', value: 'dark' }] },
    { type: 'button', title: 'Updates', description: 'Version 1.0', label: 'Check now', route: 'updates', params: {}, primary: false },
  ] },
  { key: 'help', title: 'Help & diagnostics', rows: [
    { type: 'link', title: 'Privacy policy', description: 'How LocalGateKeys handles your data', label: 'Open',
      url: 'https://localgatekeys.app/legal/privacy.html' },
  ] },
] };

describe('SettingsPage', () => {
  it('searches rows and section keywords, and the switches still work in the results', async () => {
    const api = fakeApi({ settings_page: vi.fn().mockResolvedValue(PAGE), settings_set: vi.fn().mockResolvedValue({ ok: true }) });
    render(SettingsPage, { onclose: vi.fn(), onroute: vi.fn() });
    const search = await screen.findByRole('searchbox', { name: 'Search settings' });
    await fireEvent.input(search, { target: { value: 'sleep' } });
    expect(screen.getByRole('heading', { name: 'Locking' })).toBeInTheDocument();
    expect(screen.queryByText('Theme')).toBeNull();
    await fireEvent.click(screen.getByRole('switch', { name: 'Lock on sleep' }));
    await waitFor(() => expect(api.settings_set).toHaveBeenCalledWith('lock_on_sleep', false));
    await fireEvent.input(search, { target: { value: 'dark' } });
    expect(screen.getByText('Theme')).toBeInTheDocument();
    await fireEvent.input(search, { target: { value: 'nothing here' } });
    expect(screen.getByText(/No settings match/)).toBeInTheDocument();
  });

  it('opens a link row in the browser', async () => {
    const api = fakeApi({ settings_page: vi.fn().mockResolvedValue(PAGE), system_open_url: vi.fn().mockResolvedValue({ ok: true }) });
    render(SettingsPage, { section: 'help', onclose: vi.fn(), onroute: vi.fn() });
    expect(await screen.findByText('Privacy policy')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Open' }));
    await waitFor(() => expect(api.system_open_url).toHaveBeenCalledWith('https://localgatekeys.app/legal/privacy.html'));
  });

  it('saves a choice with its typed value and shows Saved', async () => {
    const api = fakeApi({ settings_page: vi.fn().mockResolvedValue(PAGE), settings_set: vi.fn().mockResolvedValue({ ok: true, message: 'Settings saved.' }) });
    render(SettingsPage, { onclose: vi.fn(), onroute: vi.fn() });
    const select = await screen.findByLabelText('Lock after inactivity');
    await fireEvent.change(select, { target: { value: '900' } });
    await waitFor(() => expect(api.settings_set).toHaveBeenCalledWith('auto_lock_seconds', 900));
    expect(await screen.findByText('Saved')).toBeInTheDocument();
  });

  it('shows a refused value under its row', async () => {
    fakeApi({ settings_page: vi.fn().mockResolvedValue(PAGE),
      settings_set: vi.fn().mockResolvedValue({ ok: false, error: { code: 'invalid', message: 'That value cannot be used.' } }) });
    render(SettingsPage, { onclose: vi.fn(), onroute: vi.fn() });
    await fireEvent.click(await screen.findByRole('switch', { name: 'Lock on sleep' }));
    expect(await screen.findByText('That value cannot be used.')).toBeInTheDocument();
  });

  it('website icons switch is shown off with its privacy note and saves as a boolean', async () => {
    const privacy = { ok: true, saved_text: '', sections: [{ key: 'privacy', title: 'Privacy', rows: [
      { type: 'switch', key: 'strict_offline_mode', title: 'Strict offline mode', description: '', value: false },
      { type: 'switch', key: 'website_icons', title: 'Show website icons',
        description: "Shows each site's logo. Downloading it tells that site you have an account there (nothing else is sent). Works in strict offline mode.", value: false },
    ] }] };
    const api = fakeApi({ settings_page: vi.fn().mockResolvedValue(privacy), settings_set: vi.fn().mockResolvedValue({ ok: true, message: 'Settings saved.' }) });
    render(SettingsPage, { onclose: vi.fn(), onroute: vi.fn() });
    const toggle = await screen.findByRole('switch', { name: 'Show website icons' });
    expect(toggle).not.toBeChecked();
    expect(screen.getByText(/tells that site you have an account/)).toBeInTheDocument();
    await fireEvent.click(toggle);
    await waitFor(() => expect(api.settings_set).toHaveBeenCalledWith('website_icons', true));
  });

  it('buttons route instead of acting', async () => {
    fakeApi({ settings_page: vi.fn().mockResolvedValue(PAGE) });
    const onroute = vi.fn();
    render(SettingsPage, { section: 'appearance', onclose: vi.fn(), onroute });
    await fireEvent.click(await screen.findByRole('button', { name: 'Check now' }));
    expect(onroute.mock.calls[0][0]).toBe('updates');
  });
});

describe('LicencePage', () => {
  it('installs a pasted key', async () => {
    const view = { ok: true, headline: 'Free', details: ['Free plan: 3 of 4 items used'], can_remove: false, warning: false,
      pitch: 'LocalGateKeys Pro: unlimited items', purchase_url: '', upgrade: {}, pro: false };
    const api = fakeApi({ licence_view: vi.fn().mockResolvedValue(view),
      licence_install: vi.fn().mockResolvedValue({ ...view, headline: 'LocalGateKeys Pro', message: 'Licence installed for Ann.' }) });
    render(LicencePage, { onclose: vi.fn() });
    await fireEvent.input(await screen.findByLabelText('Paste your licence key'), { target: { value: 'LGK1-abc' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Install' }));
    await waitFor(() => expect(api.licence_install).toHaveBeenCalledWith('LGK1-abc'));
    expect(await screen.findByText('LocalGateKeys Pro')).toBeInTheDocument();
  });
});

describe('ProfilesPage', () => {
  it('adds a profile', async () => {
    const list = { ok: true, intro: 'Select a LocalGateKeys profile.', note: 'Locking does not sign out websites.',
      profiles: [{ id: 'p1', name: 'Alex', color: '#28C7FA', initials: 'I', active: true, photo: '' }] };
    const api = fakeApi({ profiles_manage: vi.fn().mockResolvedValue(list), profiles_create: vi.fn().mockResolvedValue({ ok: true, profile: {} }) });
    render(ProfilesPage, { onclose: vi.fn() });
    await fireEvent.input(await screen.findByLabelText('New profile name'), { target: { value: 'Work' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Add profile' }));
    await waitFor(() => expect(api.profiles_create).toHaveBeenCalledWith('Work'));
  });
});

describe('App theme and upgrade prompt', () => {
  it('applies the appearance from state and events', async () => {
    fakeApi({ vault_state: vi.fn().mockResolvedValue({ ...LOCKED, appearance: 'dark' }) });
    render(App);
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe('dark'));
    emit('appearance', { appearance: 'system' });
    await waitFor(() => expect(document.documentElement.dataset.theme).toBeUndefined());
  });

  it('shows the upgrade prompt and answers "enter"', async () => {
    const api = fakeApi({ vault_state: vi.fn().mockResolvedValue(LOCKED) });
    render(App);
    emit('modal.request', { id: 'u1', kind: 'upgrade', limit: 4, message: 'The free plan holds up to 4 items.' });
    await fireEvent.click(await screen.findByRole('button', { name: 'Enter licence' }));
    expect(api.modal_answer).toHaveBeenCalledWith('u1', 'enter');
  });
});
