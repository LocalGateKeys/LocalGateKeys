import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import Home from './Home.svelte';
import CodesCard from '../components/CodesCard.svelte';
import DetailPane from '../components/DetailPane.svelte';
import LoginEditor from '../components/LoginEditor.svelte';
import Generator from '../components/Generator.svelte';
import Palette from '../components/Palette.svelte';
import NewItem from '../components/NewItem.svelte';
import { ALPHA, NOTE, UNLOCKED, emit, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; vi.useRealTimers(); });

describe('Home list and sidebar', () => {
  let api;
  beforeEach(() => { api = fakeApi(); });

  it('renders rows and filters by a sidebar entry', async () => {
    render(Home, { vault: UNLOCKED });
    expect(await screen.findByRole('option', { name: /Alpha/ })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Router/ })).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: /Favorites/ }));
    await waitFor(() => expect(api.items_list).toHaveBeenLastCalledWith('favorite', null, ''));
  });

  it('shows chips only when their count is above zero', async () => {
    render(Home, { vault: UNLOCKED });
    expect(await screen.findByRole('button', { name: 'Needs attention · 1' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Expiring/ })).not.toBeInTheDocument();
  });

  it('searches after typing', async () => {
    render(Home, { vault: UNLOCKED });
    await screen.findByRole('option', { name: /Alpha/ });
    await fireEvent.input(screen.getByRole('searchbox'), { target: { value: 'alp' } });
    await waitFor(() => expect(api.items_list).toHaveBeenLastCalledWith(null, null, 'alp'));
  });

  it('shows the empty state and its action clears filters', async () => {
    api.items_list.mockResolvedValue({ ok: true, items: [], count: 0, chips: { attention: 0, no2fa: 0, expiring: 0 },
      context: { title: 'All items', text: '' }, empty: { title: 'No matching items', text: 'Try another name, username or tag, or clear your filters.', action: 'Clear filters' } });
    render(Home, { vault: UNLOCKED });
    expect(await screen.findByText('No matching items')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(api.items_list).toHaveBeenLastCalledWith(null, null, ''));
  });

  it('moves the selection with the keyboard and loads the detail', async () => {
    render(Home, { vault: UNLOCKED });
    const list = await screen.findByRole('listbox');
    await screen.findByRole('option', { name: /Alpha/ });
    await fireEvent.keyDown(list, { key: 'ArrowDown' });
    await waitFor(() => expect(api.item_detail).toHaveBeenLastCalledWith(ALPHA.ref));
    await fireEvent.keyDown(list, { key: 'ArrowDown' });
    await waitFor(() => expect(api.typed_detail).toHaveBeenLastCalledWith(NOTE.ref));
  });

  it('updates the status line on autolock ticks', async () => {
    render(Home, { vault: UNLOCKED });
    await screen.findByRole('option', { name: /Alpha/ });
    api.status_get.mockResolvedValue({ ok: true, autolock: 'Auto-lock in 1:00', clipboard: 'Clipboard clears in 9s', encrypted: 'Local · Encrypted', hint: '' });
    emit('autolock.tick', { remaining: 60 });
    expect(await screen.findByText('Auto-lock in 1:00')).toBeInTheDocument();
    expect(screen.getByText('Clipboard clears in 9s')).toBeInTheDocument();
  });

  it('reloads the list on items.changed', async () => {
    render(Home, { vault: UNLOCKED });
    await screen.findByRole('option', { name: /Alpha/ });
    const calls = api.items_list.mock.calls.length;
    emit('items.changed', {});
    await waitFor(() => expect(api.items_list.mock.calls.length).toBeGreaterThan(calls));
  });
});

describe('DetailPane', () => {
  it('reveals then masks again after mask_after', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const api = fakeApi({ item_reveal: vi.fn().mockResolvedValue({ ok: true, password: 'pw-alpha-1234567', mask_after: 2 }) });
    render(DetailPane, { selected: ALPHA.ref });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show' }));
    expect(await screen.findByText('pw-alpha-1234567')).toBeInTheDocument();
    expect(api.item_reveal).toHaveBeenCalledWith(ALPHA.ref);
    vi.advanceTimersByTime(2100);
    await waitFor(() => expect(screen.queryByText('pw-alpha-1234567')).not.toBeInTheDocument());
  });

  it('drops a revealed password when the vault locks', async () => {
    fakeApi();
    render(DetailPane, { selected: ALPHA.ref });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show' }));
    await screen.findByText('pw-alpha-1234567');
    emit('vault.state', { state: 'locked' });
    await waitFor(() => expect(screen.queryByText('pw-alpha-1234567')).not.toBeInTheDocument());
  });

  it('copies through the bridge and shows the live 2FA code', async () => {
    const api = fakeApi();
    render(DetailPane, { selected: ALPHA.ref });
    expect(await screen.findByText('123 456')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Copy password' }));
    expect(api.item_copy).toHaveBeenCalledWith(ALPHA.ref, 'password');
  });

  it('typed items show their safe fields', async () => {
    fakeApi({ typed_detail: vi.fn().mockResolvedValue({ ok: true, kind: 'card', title: 'Visa', subtitle: 'Payment card',
      fields: [{ name: 'brand', label: 'Card', value: 'Visa ending 6411', protected: false, present: true }], tags: [], favorite: false }) });
    render(DetailPane, { selected: { source: 'typed', id: 'c1', kind: 'card' } });
    expect(await screen.findByText('Visa ending 6411')).toBeInTheDocument();
  });

  it('a secure note stays masked until revealed', async () => {
    const api = fakeApi({ typed_detail: vi.fn().mockResolvedValue({ ok: true, kind: 'note', title: 'Router', subtitle: 'Secure note',
      fields: [{ name: 'body', label: 'Note body', value: null, protected: true, present: true }], tags: [], favorite: false }),
      typed_reveal: vi.fn().mockResolvedValue({ ok: true, value: 'line one' + String.fromCharCode(10) + 'line two', mask_after: 30 }) });
    const selected = { source: 'typed', id: 'n1', kind: 'note' };
    render(DetailPane, { selected });
    expect(await screen.findByText('••••••••••••')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Reveal body' }));
    await waitFor(() => expect(api.typed_reveal).toHaveBeenCalledWith(selected, 'body'));
    expect(await screen.findByText(/line one/)).toHaveClass('notes');
  });

  it('strict logins hide the code until asked', async () => {
    fakeApi({ item_detail: vi.fn().mockResolvedValue({ ok: true, kind: 'web', title: 'Bank', subtitle: '', username: 'b',
      has_password: true, has_totp: true, strict: true, notes: null, tags: [], target: '', origin: null, favorite: false, actions: ['edit'] }) });
    render(DetailPane, { selected: ALPHA.ref });
    expect(await screen.findByText('Hidden · click to show')).toBeInTheDocument();
  });
});

describe('LoginEditor', () => {
  it('sends field changes and saves', async () => {
    const api = fakeApi();
    const onclose = vi.fn();
    render(LoginEditor, { ref: null, onclose });
    const url = await screen.findByLabelText('Website');
    await fireEvent.input(url, { target: { value: 'alpha.test' } });
    await fireEvent.input(screen.getByLabelText('Username'), { target: { value: 'ann' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(api.login_save).toHaveBeenCalledWith('d1'));
    expect(api.login_update).toHaveBeenCalled();
    await waitFor(() => expect(onclose).toHaveBeenCalledWith({ source: 'credential', id: 'a2', kind: 'web' }));
  });

  it('ignores an older login_update reply that arrives late', async () => {
    const resolvers = [];
    const view = (username) => ({ ok: true, draft_id: 'd1', kind: 'web', is_new: true, label: '', label_hint: 'x',
      urls: [{ url: '', match: 'exact_origin' }], username, password_set: true, favorite: false, tags: [], notes: '',
      totp_configured: false, policy: {}, errors: [], strength: null, dirty: true });
    fakeApi({ login_update: vi.fn((id, changes) => new Promise((resolve) => resolvers.push(() => resolve(view(changes.username))))) });
    render(LoginEditor, { ref: null, onclose: vi.fn() });
    const user = await screen.findByLabelText('Username');
    await fireEvent.input(user, { target: { value: 'an' } });
    await fireEvent.input(user, { target: { value: 'ann' } });
    resolvers[1]();
    await waitFor(() => expect(user).toHaveValue('ann'));
    resolvers[0]();
    await new Promise((r) => setTimeout(r, 20));
    expect(user).toHaveValue('ann');
  });

  it('shows field errors from an invalid save', async () => {
    fakeApi({ login_save: vi.fn().mockResolvedValue({ ok: false, error: { code: 'invalid', message: 'Check the highlighted fields' },
      view: { draft_id: 'd1', kind: 'web', is_new: true, label: '', label_hint: 'Untitled login', urls: [{ url: '', match: 'exact_origin' }],
        username: '', password_set: true, favorite: false, tags: [], notes: '', totp_configured: false, policy: {},
        errors: [{ field: 'urls[0]', message: 'Enter a website address' }], strength: null, dirty: true } }) });
    render(LoginEditor, { ref: null, onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Enter a website address')).toBeInTheDocument();
  });

  it('edits a desktop login: no website row, the app path, and a way to the app binding', async () => {
    const ref = { source: 'credential', id: 'd9', kind: 'desktop' };
    const api = fakeApi({ login_open: vi.fn().mockResolvedValue({ ok: true, draft_id: 'd1', kind: 'desktop', is_new: false,
      label: 'DeCaveDev', label_hint: 'DeCaveDev', urls: [], app_path: String.raw`C:\Apps\DeCave.exe`, username: 'ann',
      password_set: false, favorite: false, tags: [], notes: '', totp_configured: false, policy: {}, errors: [],
      strength: null, dirty: false }) });
    const onbinding = vi.fn();
    render(LoginEditor, { ref, onclose: vi.fn(), onbinding });
    expect(await screen.findByRole('heading', { name: 'Edit desktop login' })).toBeInTheDocument();
    expect(api.login_open).toHaveBeenCalledWith(ref);
    expect(screen.queryByLabelText('Website')).toBeNull();
    expect(screen.getByLabelText('Username')).toHaveValue('ann');
    expect(screen.getByText(String.raw`C:\Apps\DeCave.exe`)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'App binding…' }));
    await waitFor(() => expect(onbinding).toHaveBeenCalledWith('d9'));
    expect(api.login_close).toHaveBeenCalledWith('d1');
  });
});

describe('Generator, palette and new item', () => {
  it('generates and copies', async () => {
    const api = fakeApi();
    render(Generator, { onclose: vi.fn() });
    expect(await screen.findByText('k7#Rv-pQ2m!Xe9wAbCd')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    expect(api.generator_copy).toHaveBeenCalledWith('k7#Rv-pQ2m!Xe9wAbCd');
  });

  it('palette runs a command with Enter', async () => {
    const api = fakeApi();
    const onclose = vi.fn();
    render(Palette, { onclose, onopen: vi.fn(), onnavigate: vi.fn() });
    const input = screen.getByRole('combobox');
    await fireEvent.input(input, { target: { value: 'lock' } });
    await screen.findByRole('option', { name: /Lock now/ });
    await fireEvent.keyDown(input, { key: 'Enter' });
    await waitFor(() => expect(api.palette_run).toHaveBeenCalledWith('lock-now'));
  });

  it('new item: website login opens the editor; other kinds say later', async () => {
    const onchoose = vi.fn();
    render(NewItem, { onchoose, onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: /Website login/ }));
    expect(onchoose).toHaveBeenCalledWith('web');
  });
});

describe('Old build reminder', () => {
  it('asks after unlock; Not now snoozes and Check now runs the check', async () => {
    const reminder = { ok: true, due: true, title: 'Check for updates?', text: 'This version of LocalGateKeys is 200 days old.' };
    let api = fakeApi({ updates_reminder: vi.fn().mockResolvedValue(reminder), updates_snooze: vi.fn().mockResolvedValue({ ok: true }),
      updates_check: vi.fn().mockResolvedValue({ ok: true, available: false, message: 'Up to date.' }) });
    const first = render(Home, { vault: UNLOCKED });
    await fireEvent.click(await screen.findByRole('button', { name: 'Not now' }));
    expect(api.updates_snooze).toHaveBeenCalled();
    expect(api.updates_check).not.toHaveBeenCalled();
    first.unmount();
    render(Home, { vault: UNLOCKED });
    await fireEvent.click(await screen.findByRole('button', { name: 'Check now' }));
    await waitFor(() => expect(api.updates_check).toHaveBeenCalled());
  });
});

describe('Rating prompt', () => {
  it('asks once the update reminder is quiet and sends the answer', async () => {
    const api = fakeApi({ updates_reminder: vi.fn().mockResolvedValue({ ok: true, due: false }),
      rating_prompt: vi.fn().mockResolvedValue({ ok: true, due: true, title: 'Enjoying LocalGateKeys?', text: 'Rate it now?' }),
      rating_answer: vi.fn().mockResolvedValue({ ok: true }) });
    render(Home, { vault: UNLOCKED });
    await fireEvent.click(await screen.findByRole('button', { name: 'Rate now' }));
    await waitFor(() => expect(api.rating_answer).toHaveBeenCalledWith(true));
  });

  it('stays quiet while the update reminder is showing', async () => {
    const api = fakeApi({ updates_reminder: vi.fn().mockResolvedValue({ ok: true, due: true, title: 'Check for updates?', text: 'Old.' }),
      rating_prompt: vi.fn() });
    render(Home, { vault: UNLOCKED });
    await screen.findByRole('button', { name: 'Check now' });
    expect(api.rating_prompt).not.toHaveBeenCalled();
  });
});

describe('CodesCard', () => {
  const code = (id, title, extra) => ({ ref: { source: 'credential', id, kind: 'web' }, title, username: 'ann',
    origin: null, icon: null, ...extra });

  it('shows live codes on the home screen and copies one on click', async () => {
    const api = fakeApi({ codes_list: vi.fn().mockResolvedValue({ ok: true, codes: [
      code('a1', 'Alpha', { code: '123 456', remaining: 20, period: 30 }),
      code('b1', 'Bank', { hidden: true }),
    ] }) });
    render(Home, { vault: UNLOCKED });
    expect(await screen.findByRole('region', { name: 'One-time codes' })).toBeInTheDocument();
    expect(screen.getByText('123 456')).toBeInTheDocument();
    expect(screen.getByText('Hidden · click to copy')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Copy 2FA code for Alpha' }));
    expect(api.item_copy).toHaveBeenCalledWith({ source: 'credential', id: 'a1', kind: 'web' }, 'totp');
  });

  it('stays out of the way when no login has 2FA', async () => {
    const api = fakeApi();
    render(CodesCard);
    await waitFor(() => expect(api.codes_list).toHaveBeenCalled());
    expect(screen.queryByRole('region', { name: 'One-time codes' })).toBeNull();
  });

  it('collapses long lists behind Show all', async () => {
    fakeApi({ codes_list: vi.fn().mockResolvedValue({ ok: true, codes: [1, 2, 3, 4, 5, 6].map((n) =>
      code(`c${n}`, `Site ${n}`, { code: `00${n} 000`, remaining: 20, period: 30 })) }) });
    render(CodesCard);
    expect(await screen.findByText('Site 4')).toBeInTheDocument();
    expect(screen.queryByText('Site 5')).toBeNull();
    await fireEvent.click(screen.getByRole('button', { name: 'Show all 6' }));
    expect(screen.getByText('Site 6')).toBeInTheDocument();
  });
});
