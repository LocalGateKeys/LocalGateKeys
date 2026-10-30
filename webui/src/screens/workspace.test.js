import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import WorkspacePages from '../components/WorkspacePages.svelte';
import OnboardingPage from '../components/OnboardingPage.svelte';
import App from '../App.svelte';
import Home from './Home.svelte';
import { UNLOCKED, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

describe('Reminders', () => {
  it('completes the chosen reminder', async () => {
    const list = { ok: true, title: 'Reminders', subtitle: 'Due dates stay encrypted.', rows: [{ id: 'r1', title: 'Passport', due: '2026-10-20', status: 'upcoming' }] };
    const api = fakeApi({ reminders_list: vi.fn().mockResolvedValue(list), reminders_complete: vi.fn().mockResolvedValue({ ...list, rows: [] }) });
    render(WorkspacePages, { kind: 'reminders', onclose: vi.fn() });
    await fireEvent.click(await screen.findByText('Passport'));
    await fireEvent.click(screen.getByRole('button', { name: 'Complete' }));
    await waitFor(() => expect(api.reminders_complete).toHaveBeenCalledWith('r1'));
    expect(await screen.findByText('Nothing coming up.')).toBeInTheDocument();
  });
});

describe('Collections', () => {
  it('adds a collection', async () => {
    const api = fakeApi({ collections_list: vi.fn().mockResolvedValue({ ok: true, collections: [] }),
      collections_create: vi.fn().mockResolvedValue({ ok: true, collections: [{ id: 'c1', name: 'Travel', description: '', archived: false }] }) });
    render(WorkspacePages, { kind: 'collections', onclose: vi.fn() });
    await fireEvent.input(await screen.findByLabelText('New collection name'), { target: { value: 'Travel' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Add collection' }));
    await waitFor(() => expect(api.collections_create).toHaveBeenCalledWith('Travel', ''));
    expect(await screen.findByText('Travel')).toBeInTheDocument();
  });
});

describe('Set up LocalGateKeys', () => {
  const steps = (current, extra = {}) => ['vault', 'unlock', 'import', 'phrase', 'browser'].map((key, i) => ({
    key, label: key, text: `${key} text`, primary: `Do ${key}`,
    state: extra[key] ?? (i === 0 ? 'done' : key === current ? 'current' : 'todo') }));
  const view = (current, extra) => ({ ok: true, title: 'Set up LocalGateKeys', subtitle: 's', steps: steps(current, extra),
    current, done: 1, total: 5, progress: '1 of 5', message: '', complete: false, card: true, hidden: false });

  it('opens with skipped steps offered again and starts a step', async () => {
    const api = fakeApi({ onboarding_show: vi.fn().mockResolvedValue(view('unlock')),
      onboarding_perform: vi.fn().mockResolvedValue({ ...view('unlock'), open: { route: 'hello', params: { startHello: true } } }) });
    const onroute = vi.fn();
    render(OnboardingPage, { onclose: vi.fn(), onroute });
    await fireEvent.click(await screen.findByRole('button', { name: 'Do unlock' }));
    await waitFor(() => expect(api.onboarding_perform).toHaveBeenCalledWith('unlock'));
    expect(api.onboarding_show).toHaveBeenCalled();
    expect(onroute.mock.calls[0].slice(0, 2)).toEqual(['hello', { startHello: true }]);
  });

  it('skips one step, or the whole setup from the first screen', async () => {
    const api = fakeApi({ onboarding_show: vi.fn().mockResolvedValue(view('unlock')),
      onboarding_skip: vi.fn().mockResolvedValue(view('import', { unlock: 'skipped' })),
      onboarding_skip_all: vi.fn().mockResolvedValue(view(null)) });
    const onclose = vi.fn();
    render(OnboardingPage, { onclose, onroute: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Skip' }));
    await waitFor(() => expect(api.onboarding_skip).toHaveBeenCalledWith('unlock'));
    expect(await screen.findByRole('button', { name: 'Do import' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Skip setup' })).toBeNull(); // not the first screen any more
  });

  it('Skip setup closes the guide', async () => {
    const api = fakeApi({ onboarding_show: vi.fn().mockResolvedValue(view('unlock')),
      onboarding_skip_all: vi.fn().mockResolvedValue(view(null)) });
    const onclose = vi.fn();
    render(OnboardingPage, { onclose, onroute: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Skip setup' }));
    await waitFor(() => expect(onclose).toHaveBeenCalled());
    expect(api.onboarding_skip_all).toHaveBeenCalled();
  });

  it('shows the vault card until it is hidden', async () => {
    const api = fakeApi({ onboarding_card: vi.fn().mockResolvedValue({ ok: true, card: true, progress: '3 of 5', done: 3, total: 5 }),
      onboarding_hide: vi.fn().mockResolvedValue({ ok: true, card: false }) });
    render(Home, { vault: UNLOCKED });
    expect(await screen.findByText('Finish setting up · 3 of 5')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Hide' }));
    await waitFor(() => expect(api.onboarding_hide).toHaveBeenCalled());
    await waitFor(() => expect(screen.queryByText('Finish setting up · 3 of 5')).toBeNull());
  });
});

describe('Startup and keys', () => {
  it('shows the legacy-data choice before anything else', async () => {
    const api = fakeApi({ vault_state: vi.fn().mockResolvedValue({ ok: true, state: 'legacy', profile: null, vault_exists: false,
      legacy: { title: 'Legacy LocalGateKeys data found', text: 'Found data.', location: 'Legacy location: C:\\old' } }),
      legacy_fresh: vi.fn().mockResolvedValue({ ok: true, state: 'locked', profile: { id: 'p1', name: 'Alex', color: '#000' }, vault_exists: false, chips: [] }) });
    render(App);
    await fireEvent.click(await screen.findByRole('button', { name: 'Start fresh' }));
    await waitFor(() => expect(api.legacy_fresh).toHaveBeenCalled());
    await waitFor(() => expect(screen.queryByText('Legacy LocalGateKeys data found')).not.toBeInTheDocument());
  });

  it('F1 opens the keyboard shortcuts but "?" in a text field does not', async () => {
    const api = fakeApi({ shortcuts_list: vi.fn().mockResolvedValue({ ok: true, title: 'Keyboard shortcuts', subtitle: 'Press Esc to close.',
      rows: [{ group: 'Main window', keys: 'Ctrl+K', description: 'Search' }] }) });
    render(Home, { vault: UNLOCKED });
    const search = await screen.findByPlaceholderText(/Search/);
    await fireEvent.keyDown(search, { key: '?' });
    expect(api.shortcuts_list).not.toHaveBeenCalled();
    await fireEvent.keyDown(window, { key: 'F1' });
    expect(await screen.findByText('Search')).toBeInTheDocument();
  });
});

describe('Passkey prompt', () => {
  it('asks which account to sign in with and answers with its id', async () => {
    const api = fakeApi({ vault_state: vi.fn().mockResolvedValue({ ...UNLOCKED }) });
    const { emit } = await import('../test/fakeApi.js');
    render(App);
    emit('modal.request', { id: 'pk1', kind: 'passkey', mode: 'get', origin: 'https://a.test', rp_id: 'a.test', profile_name: 'Ann',
      excluded: false, accounts: [{ item_id: 'i1', title: 'ann', user_name: '' }, { item_id: 'i2', title: 'bob', user_name: '' }],
      text: { title: 'Sign in with a passkey?', body: 'Site: a.test', approve_label: 'Sign in', browser_label: 'Use browser or another device', cancel_label: 'Cancel' } });
    const signIn = await screen.findByRole('button', { name: 'Sign in' });
    expect(signIn).toBeDisabled();
    await fireEvent.click(screen.getByLabelText('bob'));
    await fireEvent.click(signIn);
    expect(api.modal_answer).toHaveBeenCalledWith('pk1', { choice: 'approve', item_id: 'i2' });
  });
});
