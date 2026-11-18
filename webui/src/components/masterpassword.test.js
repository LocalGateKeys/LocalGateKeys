// Known limitation 6, step A: a master password typed into the page is cleared from the field and its
// bound state as soon as the call is sent (before Python's slow reply), on success and on error.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import MasterSheet from './MasterSheet.svelte';
import DuressSection from './DuressSection.svelte';
import PasswordModal from './PasswordModal.svelte';
import BackupPasswordSheet from './BackupPasswordSheet.svelte';
import PowerUserPanel from './PowerUserPanel.svelte';
import EmergencyAccess from './EmergencyAccess.svelte';

afterEach(() => { vi.restoreAllMocks(); delete window.pywebview; });

function install(api) {
  window.pywebview = { api };
  return api;
}

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

const FAILED = { ok: false, error: { code: 'wrong_password', message: 'That did not work.' } };

async function type(label, value) {
  await fireEvent.input(screen.getByLabelText(label, { selector: 'input' }), { target: { value } });
}

function field(label) {
  return screen.getByLabelText(label, { selector: 'input' });
}

function expectEmpty(...labels) {
  for (const label of labels) expect(field(label)).toHaveValue('');
}

describe('change master password', () => {
  const FIELDS = ['Current master password', 'New master password (at least 12 characters)', 'Enter the new password again'];

  for (const [outcome, reply] of [['success', { ok: true, notes: [] }], ['an error', FAILED]]) {
    it(`clears all three fields once sent, and after ${outcome}`, async () => {
      const answer = deferred();
      const onclose = vi.fn();
      const api = install({
        master_info: vi.fn().mockResolvedValue({ ok: true, needs_phrase: false }),
        master_change: vi.fn(() => answer.promise),
      });
      render(MasterSheet, { onclose });
      await waitFor(() => expect(api.master_info).toHaveBeenCalled());
      await type(FIELDS[0], 'old master pw 1');
      await type(FIELDS[1], 'new master pw 12');
      await type(FIELDS[2], 'new master pw 12');
      await fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
      await waitFor(() => expect(api.master_change).toHaveBeenCalledWith('old master pw 1', 'new master pw 12',
        'new master pw 12', null));
      expectEmpty(...FIELDS);
      answer.resolve(reply);
      if (reply.ok) await waitFor(() => expect(onclose).toHaveBeenCalled());
      else {
        expect(await screen.findByText('That did not work.')).toBeInTheDocument();
        expectEmpty(...FIELDS);
      }
    });
  }

  it('keeps the fields when nothing was sent (the new passwords differ)', async () => {
    const api = install({
      master_info: vi.fn().mockResolvedValue({ ok: true, needs_phrase: false }),
      master_change: vi.fn(),
    });
    render(MasterSheet, { onclose: vi.fn() });
    await waitFor(() => expect(api.master_info).toHaveBeenCalled());
    await type(FIELDS[0], 'old master pw 1');
    await type(FIELDS[1], 'new master pw 12');
    await type(FIELDS[2], 'new master pw 13');
    await fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByText('The new passwords did not match.')).toBeInTheDocument();
    expect(api.master_change).not.toHaveBeenCalled();
    expect(screen.getByLabelText(FIELDS[0])).toHaveValue('old master pw 1');
  });
});

describe('duress password set-up', () => {
  const OFF = { ok: true, pro: true, configured: false, lock_hours: 24, min_hours: 1, max_hours: 168, max_items: 2,
    folder: false, items: [] };
  const FIELDS = ['Master password', 'Duress password', 'Repeat duress password'];

  for (const [outcome, reply] of [['success', { ...OFF, configured: true, message: 'Set.' }], ['an error', FAILED]]) {
    it(`clears the master and duress passwords once sent, and after ${outcome}`, async () => {
      const answer = deferred();
      const api = install({ duress_status: vi.fn().mockResolvedValue(OFF), duress_setup: vi.fn(() => answer.promise) });
      render(DuressSection);
      await screen.findByTestId('duress');
      await type(FIELDS[0], 'real password');
      await type(FIELDS[1], 'second password');
      await type(FIELDS[2], 'second password');
      await fireEvent.click(screen.getByRole('button', { name: 'Set up' }));
      await waitFor(() => expect(api.duress_setup).toHaveBeenCalled());
      expectEmpty(...FIELDS);
      answer.resolve(reply);
      if (reply.ok) expect(await screen.findByText('Set.')).toBeInTheDocument();
      else {
        // The error is a toast; the form stays, empty.
        await answer.promise;
        await new Promise((r) => setTimeout(r, 0));
        expectEmpty(...FIELDS);
      }
    });
  }
});

describe('re-authentication prompt', () => {
  it('empties the field as the answer is handed over', async () => {
    const onanswer = vi.fn();
    render(PasswordModal, { title: 'Confirm it is you', onanswer });
    await type('Master password', 'correct horse battery');
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(onanswer).toHaveBeenCalledWith('correct horse battery');
    expect(screen.getByLabelText('Master password')).toHaveValue('');
  });
});

describe('scheduled-backup password', () => {
  for (const [outcome, reply] of [['success', { ok: true, message: 'Saved.' }], ['an error', FAILED]]) {
    it(`clears both fields once sent, and after ${outcome}`, async () => {
      const answer = deferred();
      const onclose = vi.fn();
      const api = install({ backup_password_set: vi.fn(() => answer.promise) });
      render(BackupPasswordSheet, { mode: 'set', onclose });
      await type('Backup password', 'backup password 1');
      await type('Enter the backup password again', 'backup password 1');
      await fireEvent.submit(field('Backup password').closest('form'));
      await waitFor(() => expect(api.backup_password_set).toHaveBeenCalledWith('backup password 1', 'backup password 1'));
      expectEmpty('Backup password', 'Enter the backup password again');
      answer.resolve(reply);
      if (reply.ok) await waitFor(() => expect(onclose).toHaveBeenCalledWith(true));
      else {
        expect(await screen.findByText('That did not work.')).toBeInTheDocument();
        expectEmpty('Backup password', 'Enter the backup password again');
      }
    });
  }
});

describe('backup restore test', () => {
  for (const [outcome, reply] of [['success', { ok: true, text: 'Passed.', passed: true }], ['an error', FAILED]]) {
    it(`clears the backup and vault passwords once sent, and after ${outcome}`, async () => {
      const answer = deferred();
      const api = install({
        restore_test_status: vi.fn().mockResolvedValue({ ok: true, text: 'Never run.', due: false }),
        restore_test_pick: vi.fn().mockResolvedValue({ ok: true, path: 'C:\\b.lgk', name: 'b.lgk' }),
        restore_test_run: vi.fn(() => answer.promise),
      });
      render(PowerUserPanel);
      await fireEvent.click(await screen.findByRole('button', { name: 'Test now' }));
      const backup = await screen.findByPlaceholderText('Backup password');
      const vault = screen.getByPlaceholderText('Vault password (if different)');
      await fireEvent.input(backup, { target: { value: 'backup pw 1' } });
      await fireEvent.input(vault, { target: { value: 'master pw 1' } });
      await fireEvent.submit(backup.closest('form'));
      await waitFor(() => expect(api.restore_test_run).toHaveBeenCalledWith('C:\\b.lgk', 'backup pw 1', 'master pw 1'));
      expect(backup).toHaveValue('');
      expect(vault).toHaveValue('');
      answer.resolve(reply);
      if (!reply.ok) {
        await waitFor(() => expect(screen.getByRole('button', { name: 'Run test' })).toBeInTheDocument());
        expect(screen.getByPlaceholderText('Backup password')).toHaveValue('');
        expect(screen.getByPlaceholderText('Vault password (if different)')).toHaveValue('');
      }
    });
  }
});

describe('emergency access restore', () => {
  for (const [outcome, reply] of [['success', { ok: true, message: 'restored', restored: true }], ['an error', FAILED]]) {
    it(`clears the new master password once sent, and after ${outcome}`, async () => {
      const answer = deferred();
      const ready = { ok: true, shards: [{ index: 1, holder: 'Anna' }], plan: { owner: 'Ilias', k: 2, n: 3, wait_days: 7 },
        folder: 'D:\\Shared', status: { state: 'ready', days_left: 0, missing: 0, granted: true } };
      const api = install({ heir_receive_view: vi.fn().mockResolvedValue(ready), heir_restore: vi.fn(() => answer.promise) });
      render(EmergencyAccess, { mode: 'heir', onclose: () => {} });
      await screen.findByText('Restore as a new profile', { selector: 'strong' });
      await type('New profile name', 'Inherited');
      await type('New master password', 'new pass 12345');
      await type('Confirm the new master password', 'new pass 12345');
      await fireEvent.submit(screen.getByLabelText('New master password').closest('form'));
      await waitFor(() => expect(api.heir_restore).toHaveBeenCalledWith('Inherited', 'new pass 12345', 'new pass 12345'));
      expectEmpty('New master password', 'Confirm the new master password');
      expect(screen.getByLabelText('New profile name')).toHaveValue('Inherited');
      answer.resolve(reply);
      expect(await screen.findByText(reply.ok ? 'restored' : 'That did not work.')).toBeInTheDocument();
      expectEmpty('New master password', 'Confirm the new master password');
    });
  }
});
