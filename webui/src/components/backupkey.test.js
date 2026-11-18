import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import BackupPasswordSheet from './BackupPasswordSheet.svelte';
import SettingsPage from './SettingsPage.svelte';
import RecoveryPage from './RecoveryPage.svelte';
import { fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const BACKUPS = { ok: true, saved_text: '', sections: [{ key: 'backups', title: 'Backups', rows: [
  { type: 'notice', kind: 'info', title: 'Change your backup password to finish the upgrade', text: 'Scheduled backups now lock with a public key.',
    actions: [{ label: 'Change', route: 'backup_password', params: { mode: 'change' } },
      { label: 'Dismiss', route: 'backup_password', params: { mode: 'dismiss' } }] },
  { type: 'button', title: 'Backup password', description: 'From before the upgrade (changing it is recommended)', label: 'Change',
    route: 'backup_password', params: { mode: 'change' }, primary: false },
] }] };

describe('scheduled-backup key', () => {
  it('shows the upgrade notice with its Change and Dismiss routes, never blocking the page', async () => {
    fakeApi({ settings_page: vi.fn().mockResolvedValue(BACKUPS) });
    const onroute = vi.fn();
    render(SettingsPage, { section: 'backups', onclose: vi.fn(), onroute });
    expect(await screen.findByText('Change your backup password to finish the upgrade')).toBeInTheDocument();
    expect(screen.getByText('From before the upgrade (changing it is recommended)')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(onroute).toHaveBeenCalledWith('backup_password', { mode: 'dismiss' }, expect.any(Function));
  });

  it('changes the password with the old one and the re-lock choice, then clears every field', async () => {
    const api = fakeApi({ backup_password_change: vi.fn().mockResolvedValue({ ok: true, message: 'Backup password changed.' }) });
    const onclose = vi.fn();
    render(BackupPasswordSheet, { mode: 'change', onclose });
    await fireEvent.input(screen.getByLabelText('Current backup password'), { target: { value: 'old backup password' } });
    await fireEvent.input(screen.getByLabelText('New backup password'), { target: { value: 'new backup password' } });
    await fireEvent.input(screen.getByLabelText('New backup password again'), { target: { value: 'new backup password' } });
    await fireEvent.click(screen.getByLabelText('Re-lock my scheduled backups to the new password'));
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(api.backup_password_change).toHaveBeenCalledWith(
      'old backup password', 'new backup password', 'new backup password', false));
    expect(onclose).toHaveBeenCalledWith(true);
  });

  it('resets with the recovery phrase and shows a refusal', async () => {
    const api = fakeApi({ backup_password_reset: vi.fn().mockResolvedValue({ ok: false, error: { code: 'invalid',
      message: 'This is not the recovery phrase that was active when the backup password was set on 2026-10-31.' } }) });
    render(BackupPasswordSheet, { mode: 'reset', onclose: vi.fn() });
    await fireEvent.input(screen.getByLabelText('Recovery phrase (24 words)'), { target: { value: 'abandon ability' } });
    await fireEvent.input(screen.getByLabelText('New backup password'), { target: { value: 'new backup password' } });
    await fireEvent.input(screen.getByLabelText('New backup password again'), { target: { value: 'new backup password' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(api.backup_password_reset).toHaveBeenCalledWith('abandon ability', 'new backup password', 'new backup password'));
    expect(await screen.findByRole('alert')).toHaveTextContent('not the recovery phrase');
    expect(screen.getByLabelText('Recovery phrase (24 words)')).toHaveValue('');
  });

  it('re-binds, confirms and removes with the backup password', async () => {
    const api = fakeApi({ backup_key_rebind: vi.fn().mockResolvedValue({ ok: true, message: 'ok' }),
      backup_key_remove: vi.fn().mockResolvedValue({ ok: true, message: 'ok' }) });
    const first = render(BackupPasswordSheet, { mode: 'rebind', onclose: vi.fn() });
    await fireEvent.input(screen.getByLabelText('Current backup password'), { target: { value: 'the backup password' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(api.backup_key_rebind).toHaveBeenCalledWith('the backup password'));
    first.unmount();
    render(BackupPasswordSheet, { mode: 'remove', onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Use the recovery phrase instead' }));
    await fireEvent.input(screen.getByLabelText('Recovery phrase (24 words)'), { target: { value: 'abandon ability' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(api.backup_key_remove).toHaveBeenCalledWith(null, 'abandon ability'));
  });

  it('after a rollback, confirms with the newest backup password of this device (design 16c)', async () => {
    const api = fakeApi({ backup_key_confirm: vi.fn().mockResolvedValue({ ok: false, error: { code: 'invalid',
      message: 'That is not the current backup password.' } }) });
    render(BackupPasswordSheet, { mode: 'confirmSeen', onclose: vi.fn() });
    expect(screen.getByText(/newest backup password set on this device/)).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText('Current backup password'), { target: { value: 'old leaked password' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(api.backup_key_confirm).toHaveBeenCalledWith('old leaked password'));
    expect(await screen.findByRole('alert')).toHaveTextContent('not the current backup password');
    expect(screen.getByLabelText('Current backup password')).toHaveValue('');
  });

  it('restore: the file is chosen first and its key line shown before any password', async () => {
    const api = fakeApi({
      backup_status: vi.fn().mockResolvedValue({ ok: true, can_create: true, phrase_enrolled: false, intro: 'Intro', phrase_intro: '', trial: false, kit_ready: false }),
      backup_choose: vi.fn().mockResolvedValue({ ok: true, name: 'LocalGateKeys-scheduled-x.lgk',
        key_line: 'This backup uses your current backup password (set on 2026-10-31). You will also need the master password of the backed-up vault.' }),
      backup_restore: vi.fn().mockResolvedValue({ ok: true, message: 'Restored.' }),
    });
    render(RecoveryPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: /Restore/ }));
    await waitFor(() => expect(api.backup_choose).toHaveBeenCalledWith('restore'));
    expect(await screen.findByText(/uses your current backup password/)).toBeInTheDocument();
    expect(screen.getByText('Backup: LocalGateKeys-scheduled-x.lgk')).toBeInTheDocument();
  });
});
