import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import ImportExportMenu from '../components/ImportExportMenu.svelte';
import PhoneBackupSheet from '../components/PhoneBackupSheet.svelte';
import { fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const CHOSEN = { ok: true, handle: 'h1', name: 'phone.lgkbackup', platform: 'android', created: '2026-10-20' };
const PREVIEW = { ok: true, token: 't1', lines: ['Items: 3', 'Logins: 2'], status: 'Preview is ready.' };

function api(overrides = {}) {
  return fakeApi({
    phone_backup_choose: vi.fn().mockResolvedValue(CHOSEN),
    phone_backup_preview: vi.fn().mockResolvedValue(PREVIEW),
    phone_backup_commit: vi.fn().mockResolvedValue({ ok: true, lines: ['Items: 3'], status: 'Restored 3 items.', changed: true }),
    phone_backup_cancel: vi.fn().mockResolvedValue({ ok: true }),
    ...overrides,
  });
}

describe('Restore phone backup', () => {
  it('menu hides Restore phone backup until a phone app writes backups', () => {
    render(ImportExportMenu, { onpick: vi.fn(), onclose: vi.fn() });
    expect(screen.queryByRole('menuitem', { name: /Restore phone backup…/ })).toBeNull();
    expect(screen.getAllByRole('menuitem')).toHaveLength(3);
  });

  it('menu offers Restore phone backup when enabled', async () => {
    const onpick = vi.fn();
    render(ImportExportMenu, { onpick, onclose: vi.fn(), phoneBackup: true });
    await fireEvent.click(screen.getByRole('menuitem', { name: /Restore phone backup…/ }));
    expect(onpick).toHaveBeenCalledWith('phone-backup');
    expect(screen.getByText('Bring back items from an Android or iPhone backup file')).toBeInTheDocument();
  });

  it('choose, preview and restore call the bridge in order and clear the password', async () => {
    const a = api();
    const onclose = vi.fn();
    render(PhoneBackupSheet, { onclose });
    const restore = screen.getByRole('button', { name: 'Restore' });
    expect(restore).toBeDisabled();
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    expect(await screen.findByText('Android backup from 2026-10-20')).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText('Backup password'), { target: { value: 'phone pw 123' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    expect(await screen.findByText(/Logins: 2/)).toBeInTheDocument();
    expect(a.phone_backup_preview).toHaveBeenCalledWith('h1', 'phone pw 123');
    await fireEvent.click(screen.getByRole('button', { name: 'Restore' }));
    await waitFor(() => expect(a.phone_backup_commit).toHaveBeenCalledWith('t1', 'h1'));
    await waitFor(() => expect(onclose).toHaveBeenCalled());
    expect(screen.getByLabelText('Backup password')).toHaveValue('');
  });

  it('shows iPhone backups by name', async () => {
    api({ phone_backup_choose: vi.fn().mockResolvedValue({ ...CHOSEN, platform: 'ios' }) });
    render(PhoneBackupSheet, { onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    expect(await screen.findByText('iPhone backup from 2026-10-20')).toBeInTheDocument();
  });

  it('a wrong password shows the error and keeps Restore disabled', async () => {
    const a = api({ phone_backup_preview: vi.fn().mockResolvedValue({ ok: false, error: { code: 'invalid', message: 'Wrong password, or the file is damaged.' } }) });
    render(PhoneBackupSheet, { onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    await fireEvent.input(await screen.findByLabelText('Backup password'), { target: { value: 'nope' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Wrong password, or the file is damaged.');
    expect(screen.getByRole('button', { name: 'Restore' })).toBeDisabled();
    expect(screen.getByLabelText('Backup password')).toHaveValue('');
    expect(a.phone_backup_commit).not.toHaveBeenCalled();
  });

  it('closing the sheet calls phone_backup_cancel', async () => {
    const a = api();
    const { unmount } = render(PhoneBackupSheet, { onclose: vi.fn() });
    unmount();
    await waitFor(() => expect(a.phone_backup_cancel).toHaveBeenCalled());
  });

  it('editing the password after a preview disables Restore again', async () => {
    api();
    render(PhoneBackupSheet, { onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    const pwField = await screen.findByLabelText('Backup password');
    await fireEvent.input(pwField, { target: { value: 'pw one' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    await screen.findByText(/Logins: 2/);
    expect(screen.getByRole('button', { name: 'Restore' })).toBeEnabled();
    await fireEvent.input(pwField, { target: { value: 'pw one2' } });
    expect(screen.getByRole('button', { name: 'Restore' })).toBeDisabled();
  });

  it('changed:false keeps the sheet open and shows the status', async () => {
    api({ phone_backup_commit: vi.fn().mockResolvedValue({ ok: true, lines: [], status: 'Nothing new to restore.', changed: false }) });
    const onclose = vi.fn();
    render(PhoneBackupSheet, { onclose });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    await fireEvent.input(await screen.findByLabelText('Backup password'), { target: { value: 'pw' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    await fireEvent.click(await screen.findByRole('button', { name: 'Restore' }).then(async (b) => { await waitFor(() => expect(b).toBeEnabled()); return b; }));
    expect(await screen.findByRole('status')).toHaveTextContent('Nothing new to restore.');
    expect(onclose).not.toHaveBeenCalled();
  });

  it('a cancelled choose shows no error', async () => {
    const a = api({ phone_backup_choose: vi.fn().mockResolvedValue({ ok: false, error: { code: 'cancelled', message: 'Cancelled.' } }) });
    render(PhoneBackupSheet, { onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    await waitFor(() => expect(a.phone_backup_choose).toHaveBeenCalled());
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('a failed commit shows the error and needs a new preview', async () => {
    api({ phone_backup_commit: vi.fn().mockResolvedValue({ ok: false, error: { code: 'busy', message: 'Too many attempts. Try again in 30 seconds.' } }) });
    const onclose = vi.fn();
    render(PhoneBackupSheet, { onclose });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    await fireEvent.input(await screen.findByLabelText('Backup password'), { target: { value: 'pw' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    await screen.findByText(/Logins: 2/);
    await fireEvent.click(screen.getByRole('button', { name: 'Restore' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Too many attempts');
    expect(screen.getByRole('button', { name: 'Restore' })).toBeDisabled();
    expect(screen.queryByText(/Logins: 2/)).toBeNull();
    expect(onclose).not.toHaveBeenCalled();
  });

  it('a second Preview click while one is pending makes no second call', async () => {
    let release;
    const a = api({ phone_backup_preview: vi.fn(() => new Promise((res) => { release = () => res(PREVIEW); })) });
    render(PhoneBackupSheet, { onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    await fireEvent.input(await screen.findByLabelText('Backup password'), { target: { value: 'pw' } });
    const preview = screen.getByRole('button', { name: 'Preview' });
    await fireEvent.click(preview);
    await fireEvent.click(preview);
    expect(a.phone_backup_preview).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Restore' })).toHaveTextContent('Restore');
    release();
    await screen.findByText(/Logins: 2/);
  });

  it('while a restore is pending Restore shows Restoring and the other buttons are disabled', async () => {
    let release;
    api({ phone_backup_commit: vi.fn(() => new Promise((res) => { release = () => res({ ok: true, lines: [], status: 'Restored.', changed: false }); })) });
    render(PhoneBackupSheet, { onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    await fireEvent.input(await screen.findByLabelText('Backup password'), { target: { value: 'pw' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    await screen.findByText(/Logins: 2/);
    await fireEvent.click(screen.getByRole('button', { name: 'Restore' }));
    expect(await screen.findByRole('button', { name: 'Restoring…' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Choose file…' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Preview' })).toBeDisabled();
    release();
    await screen.findByRole('button', { name: 'Restore' });
  });
});
