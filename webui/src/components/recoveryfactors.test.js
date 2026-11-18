import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import RecoveryPage from './RecoveryPage.svelte';
import { fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const STATUS = { ok: true, can_create: true, phrase_enrolled: true, intro: 'Intro', phrase_intro: '', trial: false, kit_ready: false };
const CHOSEN = { ok: true, name: 'backup.lgk', key_line: 'Key line.' };
const NEEDS_KEYFILE = { ok: false, error: { code: 'factor_required', message: 'This vault also needs its key file.' } };
const PROMPT = { ok: true, kinds: ['keyfile'], yubikey_slot: null, keyfile: null, yubikey_ready: false, phrase_allowed: true };

async function openRestore(api) {
  render(RecoveryPage, { onclose: vi.fn() });
  await fireEvent.click(await screen.findByRole('button', { name: /Restore/ }));
  await waitFor(() => expect(api.backup_choose).toHaveBeenCalledWith('restore'));
  await fireEvent.input(await screen.findByLabelText('Backup password'), { target: { value: 'backup pw' } });
  await fireEvent.input(screen.getByLabelText('Vault password from when the backup was made'), { target: { value: 'vault pw' } });
  await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
}

describe('restoring a backup whose vault has a key file / YubiKey', () => {
  it('asks for the key file, clears the passwords once sent and retries with them typed again', async () => {
    const api = fakeApi({
      backup_status: vi.fn().mockResolvedValue(STATUS),
      backup_choose: vi.fn().mockResolvedValue(CHOSEN),
      backup_restore: vi.fn().mockResolvedValueOnce(NEEDS_KEYFILE)
        .mockResolvedValueOnce({ ok: true, message: 'Restored.', restored: true }),
      backup_factors: vi.fn().mockResolvedValue(PROMPT),
      backup_factor_keyfile: vi.fn().mockResolvedValue({ ...PROMPT, keyfile: 'vault.keyx' }),
    });
    await openRestore(api);
    expect(await screen.findByText('This vault also needs its key file.')).toBeInTheDocument();
    expect(screen.getByText("This backup's vault also needs its key file or YubiKey")).toBeInTheDocument();
    // Not kept for the retry: the page holds no password while it waits or asks for the factor.
    expect(screen.getByLabelText('Backup password')).toHaveValue('');
    expect(screen.getByLabelText('Vault password from when the backup was made')).toHaveValue('');
    expect(screen.getByText('The passwords were cleared for safety. Type both again, then continue.')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Choose key file…' }));
    expect(await screen.findByText('Key file: vault.keyx')).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText('Backup password'), { target: { value: 'backup pw' } });
    await fireEvent.input(screen.getByLabelText('Vault password from when the backup was made'), { target: { value: 'vault pw' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(api.backup_restore).toHaveBeenCalledTimes(2));
    expect(api.backup_restore).toHaveBeenLastCalledWith('Restored profile', 'backup pw', 'vault pw');
    expect(await screen.findByText('Restored.')).toBeInTheDocument();
  });

  it('offers the recovery phrase instead and sends it with a new master password', async () => {
    const api = fakeApi({
      backup_status: vi.fn().mockResolvedValue(STATUS),
      backup_choose: vi.fn().mockResolvedValue(CHOSEN),
      backup_restore: vi.fn().mockResolvedValue(NEEDS_KEYFILE),
      backup_factors: vi.fn().mockResolvedValue({ ...PROMPT, kinds: ['keyfile', 'yubikey-hmac'], yubikey_slot: 2 }),
      backup_restore_phrase: vi.fn().mockResolvedValue({ ok: true, restored: true,
        message: 'Restored. Key file / YubiKey removed; add them again.' }),
    });
    await openRestore(api);
    expect(await screen.findByText('A YubiKey cannot be used here yet. Restore with the recovery phrase instead.')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Use recovery phrase instead' }));
    expect(screen.getByText('Restore with the recovery phrase')).toBeInTheDocument();
    expect(screen.getByLabelText('Backup password')).toHaveValue('');
    await fireEvent.input(screen.getByLabelText('Backup password'), { target: { value: 'backup pw' } });
    await fireEvent.input(screen.getByLabelText('Recovery phrase (24 words)'), { target: { value: 'word '.repeat(24) } });
    await fireEvent.input(screen.getByLabelText('New master password'), { target: { value: 'new master pw 1' } });
    await fireEvent.input(screen.getByLabelText('Confirm new master password'), { target: { value: 'new master pw 1' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(api.backup_restore_phrase).toHaveBeenCalledWith(
      'Restored profile', 'backup pw', 'word '.repeat(24), 'new master pw 1', 'new master pw 1'));
    expect(await screen.findByText('Restored. Key file / YubiKey removed; add them again.')).toBeInTheDocument();
  });
});
