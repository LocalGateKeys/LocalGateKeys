import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import Unlock from './Unlock.svelte';
import { LOCKED, emit, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const VAULT = { ...LOCKED, hello: false, camera: false, chips: [], backoff: 0 };
const MISMATCH = 'This is not the key file used for this vault.';

async function typeAndUnlock(password = 'correct horse battery') {
  await fireEvent.input(screen.getByLabelText('Master password'), { target: { value: password } });
  await fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));
}

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

describe('the master password leaves the page as soon as it is sent', () => {
  for (const [outcome, reply] of [
    ['success', { ok: true, state: 'unlocked' }],
    ['a wrong password', { ok: false, error: { code: 'wrong_password', message: 'Wrong master password.' } }],
  ]) {
    it(`clears the field before the reply arrives, and after ${outcome}`, async () => {
      const answer = deferred();
      const api = fakeApi({ vault_unlock: vi.fn(() => answer.promise) });
      render(Unlock, { vault: VAULT });
      const field = screen.getByLabelText('Master password');
      await typeAndUnlock('correct horse battery');
      await waitFor(() => expect(api.vault_unlock).toHaveBeenCalledWith('correct horse battery'));
      // Still waiting for Python (Argon2, a YubiKey touch): nothing left to show or reveal.
      expect(field).toHaveValue('');
      answer.resolve(reply);
      await waitFor(() => expect(screen.getByRole('button', { name: 'Unlock' })).not.toBeDisabled());
      expect(field).toHaveValue('');
      if (!reply.ok) {
        expect(await screen.findByText('Wrong master password.')).toBeInTheDocument();
        // The next try starts from the same, empty field.
        await typeAndUnlock('second try password');
        await waitFor(() => expect(api.vault_unlock).toHaveBeenLastCalledWith('second try password'));
        expect(field).toHaveValue('');
      }
    });
  }

  it('clears both fields when creating a vault', async () => {
    const answer = deferred();
    const api = fakeApi({ vault_create: vi.fn(() => answer.promise) });
    render(Unlock, { vault: { ...VAULT, vault_exists: false } });
    await fireEvent.input(screen.getByLabelText('Master password'), { target: { value: 'new master pw 1' } });
    await fireEvent.input(screen.getByLabelText('Confirm password'), { target: { value: 'new master pw 1' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Create vault' }));
    await waitFor(() => expect(api.vault_create).toHaveBeenCalledWith('new master pw 1', 'new master pw 1'));
    expect(screen.getByLabelText('Master password')).toHaveValue('');
    expect(screen.getByLabelText('Confirm password')).toHaveValue('');
    answer.resolve({ ok: false, error: { code: 'mismatch', message: 'The passwords do not match.' } });
    expect(await screen.findByText('The passwords do not match.')).toBeInTheDocument();
    expect(screen.getByLabelText('Master password')).toHaveValue('');
  });
});

describe('Unlock with a key file / YubiKey', () => {
  it('has no factor row for a vault without factors', () => {
    fakeApi();
    render(Unlock, { vault: VAULT });
    expect(screen.queryByRole('button', { name: 'Choose key file…' })).not.toBeInTheDocument();
  });

  it('unlocks with the remembered key file (no path sent)', async () => {
    const api = fakeApi({ vault_unlock: vi.fn().mockResolvedValue({ ok: true, state: 'unlocked' }) });
    render(Unlock, { vault: { ...VAULT, factors: [{ kind: 'keyfile', slot: null }], keyfile_name: 'vault.keyx', keyfile_remember: true } });
    expect(screen.getByText('Key file: vault.keyx')).toBeInTheDocument();
    await typeAndUnlock();
    await waitFor(() => expect(api.vault_unlock).toHaveBeenCalledWith('correct horse battery'));
  });

  it('sends the picked key file and shows a mismatch by its own message', async () => {
    const api = fakeApi({
      factors_pick_keyfile: vi.fn().mockResolvedValue({ ok: true, name: 'other.keyx' }),
      vault_unlock: vi.fn().mockResolvedValue({ ok: false, error: { code: 'factor_mismatch', message: MISMATCH } }),
    });
    render(Unlock, { vault: { ...VAULT, factors: [{ kind: 'keyfile', slot: null }], keyfile_name: null, keyfile_remember: true } });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose key file…' }));
    expect(await screen.findByText('Key file: other.keyx')).toBeInTheDocument();
    await typeAndUnlock();
    await waitFor(() => expect(api.vault_unlock).toHaveBeenCalledWith('correct horse battery', true));
    expect(await screen.findByText(MISMATCH)).toBeInTheDocument();
  });

  it('shows "Touch your YubiKey" while waiting and says nothing after a cancel', async () => {
    let finish;
    const api = fakeApi({
      vault_unlock: vi.fn(() => new Promise((r) => { finish = r; })),
      factors_cancel: vi.fn().mockResolvedValue({ ok: true }),
    });
    render(Unlock, { vault: { ...VAULT, factors: [{ kind: 'yubikey-hmac', slot: 2 }] } });
    expect(screen.getByText('Insert your YubiKey (slot 2) and touch it when it blinks.')).toBeInTheDocument();
    await typeAndUnlock();
    emit('factors.touch', { waiting: true, slot: 2 });
    expect(await screen.findByText('Touch your YubiKey')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(api.factors_cancel).toHaveBeenCalled();
    emit('factors.touch', { waiting: false, slot: 2 });
    finish({ ok: false, error: { code: 'cancelled', message: 'Cancelled.' } });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Unlock' })).not.toBeDisabled());
    expect(screen.queryByText('Cancelled.')).not.toBeInTheDocument();
  });

  it('shows the YubiKey errors from Python', async () => {
    fakeApi({ vault_unlock: vi.fn().mockResolvedValue({ ok: false, error: { code: 'yubikey_touch_timeout', message: 'No touch detected. Touch your YubiKey when it blinks.' } }) });
    render(Unlock, { vault: { ...VAULT, factors: [{ kind: 'yubikey-hmac', slot: 2 }] } });
    await typeAndUnlock();
    expect(await screen.findByText('No touch detected. Touch your YubiKey when it blinks.')).toBeInTheDocument();
  });
});
