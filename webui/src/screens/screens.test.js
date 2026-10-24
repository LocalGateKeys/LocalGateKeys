import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import App from '../App.svelte';
import ProfileChooser from './ProfileChooser.svelte';
import Unlock from './Unlock.svelte';

const PROFILE = { id: 'p1', name: 'Alex', color: '#2b6fe0' };
const locked = { ok: true, state: 'locked', profile: PROFILE, vault_exists: true, autolock_seconds: 300 };

function fakeApi(overrides = {}) {
  const api = {
    vault_state: vi.fn().mockResolvedValue(locked),
    vault_unlock: vi.fn().mockResolvedValue({ ...locked, state: 'unlocked' }),
    vault_create: vi.fn().mockResolvedValue({ ...locked, state: 'unlocked' }),
    vault_lock: vi.fn().mockResolvedValue(locked),
    profiles_list: vi.fn().mockResolvedValue({ ok: true, profiles: [{ ...PROFILE, active: true }, { id: 'p2', name: 'Work', color: '#7a4a2a', active: false }] }),
    profiles_select: vi.fn().mockResolvedValue({ ...locked, profile: { id: 'p2', name: 'Work', color: '#7a4a2a' } }),
    modal_answer: vi.fn().mockResolvedValue({ ok: true, accepted: true }),
    window_minimize: vi.fn(), window_toggle_maximize: vi.fn(), window_close: vi.fn(),
    ...overrides,
  };
  window.pywebview = { api };
  return api;
}

function emit(name, detail) {
  window.dispatchEvent(new CustomEvent('lgk', { detail: { name, detail } }));
}

afterEach(() => { delete window.pywebview; });

describe('Unlock', () => {
  it('submits the password and shows the vault error', async () => {
    const api = fakeApi({
      vault_unlock: vi.fn().mockResolvedValue({ ok: false, error: { code: 'wrong_password', message: 'Incorrect master password.' } }),
    });
    render(Unlock, { vault: locked });
    await fireEvent.input(screen.getByLabelText('Master password'), { target: { value: 'nope nope nope' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));
    expect(api.vault_unlock).toHaveBeenCalledWith('nope nope nope');
    expect(await screen.findByRole('alert')).toHaveTextContent('Incorrect master password.');
    expect(screen.getByLabelText('Master password')).toHaveValue('');
  });

  it('clears the password after a successful unlock too', async () => {
    fakeApi();
    render(Unlock, { vault: locked });
    await fireEvent.input(screen.getByLabelText('Master password'), { target: { value: 'correct horse battery' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));
    await waitFor(() => expect(screen.getByLabelText('Master password')).toHaveValue(''));
  });

  it('disables the button while unlocking', async () => {
    let resolve;
    fakeApi({ vault_unlock: vi.fn(() => new Promise((r) => { resolve = r; })) });
    render(Unlock, { vault: locked });
    await fireEvent.input(screen.getByLabelText('Master password'), { target: { value: 'correct horse battery' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));
    expect(screen.getByRole('button', { name: 'Unlocking…' })).toBeDisabled();
    resolve({ ...locked, state: 'unlocked' });
  });

  it('create mode asks twice and calls vault_create', async () => {
    const api = fakeApi();
    render(Unlock, { vault: { ...locked, vault_exists: false } });
    expect(screen.getByText(/at least 12 characters/)).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText('Master password'), { target: { value: 'correct horse battery' } });
    await fireEvent.input(screen.getByLabelText('Confirm password'), { target: { value: 'correct horse battery' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Create vault' }));
    expect(api.vault_create).toHaveBeenCalledWith('correct horse battery', 'correct horse battery');
  });

  it('shows the throttle message', async () => {
    fakeApi({ vault_unlock: vi.fn().mockResolvedValue({ ok: false, error: { code: 'throttled', message: 'Too many incorrect master-password attempts. Try again in 30 s.' } }) });
    render(Unlock, { vault: locked });
    await fireEvent.input(screen.getByLabelText('Master password'), { target: { value: 'x' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Try again in 30 s.');
  });
});

describe('ProfileChooser', () => {
  it('lists profiles and selects one', async () => {
    const api = fakeApi();
    const onchosen = vi.fn();
    render(ProfileChooser, { onchosen });
    await fireEvent.click(await screen.findByRole('button', { name: /Work/ }));
    expect(api.profiles_select).toHaveBeenCalledWith('p2');
    await waitFor(() => expect(onchosen).toHaveBeenCalled());
  });

  it('adds a profile and opens it', async () => {
    const api = fakeApi({ profiles_create: vi.fn().mockResolvedValue({ ok: true, profile: { id: 'p3', name: 'Kids' } }) });
    const onchosen = vi.fn();
    render(ProfileChooser, { onchosen });
    await fireEvent.click(await screen.findByRole('button', { name: /Add profile/ }));
    await fireEvent.input(screen.getByLabelText('Profile name'), { target: { value: ' Kids ' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
    await waitFor(() => expect(api.profiles_create).toHaveBeenCalledWith('Kids'));
    expect(api.profiles_select).toHaveBeenCalledWith('p3');
    await waitFor(() => expect(onchosen).toHaveBeenCalled());
  });
});

describe('App', () => {
  beforeEach(() => { fakeApi(); });

  it('reads vault_state on mount and routes on vault.state events', async () => {
    render(App);
    expect(await screen.findByLabelText('Master password')).toBeInTheDocument();
    expect(window.pywebview.api.vault_state).toHaveBeenCalled();
    emit('vault.state', { ...locked, state: 'unlocked' });
    expect(await screen.findByRole('button', { name: 'Lock' })).toBeInTheDocument();
    emit('vault.state', locked);
    expect(await screen.findByLabelText('Master password')).toBeInTheDocument();
  });

  it('renders a confirm modal.request and answers it', async () => {
    render(App);
    await screen.findByLabelText('Master password');
    emit('modal.request', { id: 'r1', kind: 'confirm', title: 'Save new login?', message: 'Origin: https://a.test' });
    await fireEvent.click(await screen.findByRole('button', { name: 'Allow' }));
    expect(window.pywebview.api.modal_answer).toHaveBeenCalledWith('r1', true);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('shows a Python notice until OK, without answering a request', async () => {
    render(App);
    await screen.findByLabelText('Master password');
    emit('notice', { kind: 'error', title: 'Rollback protection was reset', message: 'A new record has been written.' });
    expect(await screen.findByText('Rollback protection was reset')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Deny' })).not.toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(window.pywebview.api.modal_answer).not.toHaveBeenCalled();
  });

  it('modal.cancel removes a pending modal', async () => {
    render(App);
    await screen.findByLabelText('Master password');
    emit('modal.request', { id: 'r2', kind: 'confirm', title: 'Approve card fill?', message: '' });
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    emit('modal.cancel', { ids: ['r2'] });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('declines request kinds this build cannot show yet', async () => {
    render(App);
    await screen.findByLabelText('Master password');
    emit('modal.request', { id: 'r3', kind: 'not-a-real-kind' });
    await waitFor(() => expect(window.pywebview.api.modal_answer).toHaveBeenCalledWith('r3', { choice: 'cancel' }));
  });
});
