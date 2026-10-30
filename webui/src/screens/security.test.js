import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import SecurityPage from '../components/SecurityPage.svelte';
import HealthPage from '../components/HealthPage.svelte';
import MasterSheet from '../components/MasterSheet.svelte';
import RecoveryPage from '../components/RecoveryPage.svelte';
import Unlock from './Unlock.svelte';
import { LOCKED, emit, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const CENTER = {
  ok: true, score: 72, label: 'Good', headline: 'Good overall. Fixing the flagged logins below would bring you to 100.',
  issues: [{ key: 'weak', count: 1, title: 'Weak passwords', description: 'Alpha', tone: 'warning',
    action: { label: 'Review 1', route: 'health', params: { filter: 'weak' } } }],
  panels: [{ title: 'Privacy', rows: [{ label: 'Breach checks', meta: 'Off', meta_tone: 'neutral',
    action: { label: 'Turn on', route: 'set', params: { key: 'breach_check_enabled', value: true } } }] }],
  footnote: 'Breach checks send only the first 5 characters of a password hash.',
};
const REPORT = {
  ok: true, summary: '2 logins · 1 weak · 0 reused · 2 without 2FA · 0 older than a year',
  subtitle: 'Local pattern checks are guidance, not a guarantee.', footer: 'No check is performed automatically.',
  filters: [{ label: 'All', key: null }, { label: 'Weak', key: 'weak' }],
  rows: [{ id: 'a1', label: 'Alpha', username: 'ann', score: 1, categories: ['weak'], findings: 'Weak', breach: 'Not checked' }],
  running: false,
};

describe('SecurityPage', () => {
  it('routes issue actions and flips privacy switches through Python', async () => {
    const api = fakeApi({ security_center: vi.fn().mockResolvedValue(CENTER), security_set: vi.fn().mockResolvedValue({ ok: true, message: 'Settings saved.' }) });
    const onroute = vi.fn();
    render(SecurityPage, { onclose: vi.fn(), onroute });
    await fireEvent.click(await screen.findByRole('button', { name: 'Review 1' }));
    expect(onroute).toHaveBeenCalledWith('health', { filter: 'weak' });
    await fireEvent.click(screen.getByRole('button', { name: 'Turn on' }));
    await waitFor(() => expect(api.security_set).toHaveBeenCalledWith('breach_check_enabled', true));
  });
});

describe('HealthPage', () => {
  it('shows the summary, checks one login and follows progress events', async () => {
    const api = fakeApi({ health_report: vi.fn().mockResolvedValue(REPORT), health_scan: vi.fn().mockResolvedValue({ ok: true, job: 'health' }), health_cancel: vi.fn().mockResolvedValue({ ok: true }) });
    render(HealthPage, { onclose: vi.fn(), onopen: vi.fn() });
    expect(await screen.findByText(REPORT.summary)).toBeInTheDocument();
    await fireEvent.click(screen.getByText('Alpha'));
    await fireEvent.click(screen.getByRole('button', { name: 'Check selected with HIBP' }));
    expect(api.health_scan).toHaveBeenCalledWith(['a1']);
    emit('job.progress', { job: 'health', text: 'Checking… 1 of 1 unique passwords' });
    expect(await screen.findByText('Checking… 1 of 1 unique passwords')).toBeInTheDocument();
    emit('job.done', { job: 'health', ok: true, message: 'Checked 1 unique passwords · 0 logins exposed · 0 errors.' });
    await waitFor(() => expect(api.health_report).toHaveBeenCalledTimes(2));
  });
});

describe('HealthPage blocked by a setting', () => {
  const fix = { section: 'privacy', key: 'breach_check_enabled', value: true, label: 'Turn on and check' };
  const blockedApi = () => fakeApi({
    health_report: vi.fn().mockResolvedValue(REPORT),
    health_scan: vi.fn().mockResolvedValueOnce({ ok: false, error: { code: 'needs_setting', message: 'Breach checks are off.', fix } })
      .mockResolvedValue({ ok: true, job: 'health' }),
    health_cancel: vi.fn().mockResolvedValue({ ok: true }),
    settings_set: vi.fn().mockResolvedValue({ ok: true }),
  });

  it('turns the setting on and runs the scan again', async () => {
    const api = blockedApi();
    render(HealthPage, { onclose: vi.fn(), onopen: vi.fn(), onroute: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Scan all with HIBP' }));
    expect(await screen.findByText('Breach checks are off.')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Turn on and check' }));
    expect(api.settings_set).toHaveBeenCalledWith('breach_check_enabled', true);
    await waitFor(() => expect(api.health_scan).toHaveBeenCalledTimes(2));
    expect(api.health_scan).toHaveBeenLastCalledWith(null);
  });

  it('opens the Privacy settings section', async () => {
    blockedApi();
    const onroute = vi.fn();
    render(HealthPage, { onclose: vi.fn(), onopen: vi.fn(), onroute });
    await fireEvent.click(await screen.findByRole('button', { name: 'Scan all with HIBP' }));
    await fireEvent.click(await screen.findByRole('button', { name: 'Open settings' }));
    expect(onroute).toHaveBeenCalledWith('settings', { section: 'privacy' }, expect.any(Function));
  });
});

describe('HealthPage breach state', () => {
  it('marks a found breach by its state, not by the English text', async () => {
    fakeApi({ health_report: vi.fn().mockResolvedValue({ ...REPORT, rows: [{ ...REPORT.rows[0], breach: 'In 3 Lecks gefunden', breach_state: 'found' }] }),
      health_cancel: vi.fn().mockResolvedValue({ ok: true }) });
    render(HealthPage, { onclose: vi.fn(), onopen: vi.fn(), onchangepassword: vi.fn() });
    const text = await screen.findByText('In 3 Lecks gefunden');
    expect(text.classList.contains('bad')).toBe(true);
    await fireEvent.click(screen.getByText('Alpha'));
    expect(screen.getByRole('button', { name: 'Change password' })).not.toBeDisabled();
  });
});

describe('HealthPage shortcuts', () => {
  it('offers Show all on an empty filter and Change password for the picked login', async () => {
    const api = fakeApi({ health_report: vi.fn().mockResolvedValue({ ...REPORT, rows: [] }), health_cancel: vi.fn().mockResolvedValue({ ok: true }) });
    render(HealthPage, { filter: 'weak', onclose: vi.fn(), onopen: vi.fn(), onchangepassword: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show all' }));
    expect(api.health_report).toHaveBeenLastCalledWith(null);
    expect(screen.getByRole('button', { name: 'Change password' })).toBeDisabled();
  });
});

describe('MasterSheet', () => {
  it('refuses a mismatch locally and sends one call otherwise', async () => {
    const api = fakeApi({ master_info: vi.fn().mockResolvedValue({ ok: true, needs_phrase: false }), master_change: vi.fn().mockResolvedValue({ ok: true, notes: [] }) });
    const onclose = vi.fn();
    render(MasterSheet, { onclose });
    await fireEvent.input(await screen.findByLabelText('Current master password'), { target: { value: 'old password 1' } });
    await fireEvent.input(screen.getByLabelText('New master password (at least 12 characters)'), { target: { value: 'new password 12' } });
    await fireEvent.input(screen.getByLabelText('Enter the new password again'), { target: { value: 'different 1234' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByText('The new passwords did not match.')).toBeInTheDocument();
    expect(api.master_change).not.toHaveBeenCalled();
    await fireEvent.input(screen.getByLabelText('Enter the new password again'), { target: { value: 'new password 12' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
    await waitFor(() => expect(api.master_change).toHaveBeenCalledWith('old password 1', 'new password 12', 'new password 12', null));
    await waitFor(() => expect(onclose).toHaveBeenCalled());
  });
});

describe('RecoveryPage', () => {
  const STATUS = { ok: true, can_create: true, phrase_enrolled: false, intro: 'Backups are encrypted files.', phrase_intro: 'A 24-word recovery phrase.', trial: false, kit_ready: false };
  const WORDS = Array.from({ length: 24 }, (_, i) => `word${i + 1}`);

  it('creates a backup and clears the passwords', async () => {
    const api = fakeApi({ backup_status: vi.fn().mockResolvedValue(STATUS), backup_create: vi.fn().mockResolvedValue({ ok: true, message: 'Encrypted backup created. Your vault password was not stored in the backup.' }) });
    render(RecoveryPage, { onclose: vi.fn() });
    await fireEvent.click((await screen.findAllByRole('button', { name: 'Create…' }))[0]);
    await fireEvent.input(screen.getByLabelText('Backup password'), { target: { value: 'backup pw 12345' } });
    await fireEvent.input(screen.getByLabelText('Confirm backup password'), { target: { value: 'backup pw 12345' } });
    await fireEvent.input(screen.getByLabelText('Vault password'), { target: { value: 'vault pw 12345' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(api.backup_create).toHaveBeenCalledWith('backup pw 12345', 'backup pw 12345', 'vault pw 12345'));
    expect(await screen.findByText(/Encrypted backup created/)).toBeInTheDocument();
  });

  it('shows the phrase once and confirms the challenge words', async () => {
    const api = fakeApi({
      backup_status: vi.fn().mockResolvedValue(STATUS),
      phrase_create: vi.fn().mockResolvedValue({ ok: true, token: 't1', words: WORDS, positions: [2, 9, 20], intro: 'Write these 24 words down.' }),
      phrase_confirm: vi.fn().mockResolvedValue({ ok: true, confirmed: true, message: 'Recovery phrase confirmed.' }),
    });
    render(RecoveryPage, { onclose: vi.fn() });
    await screen.findAllByRole('button', { name: 'Create…' });
    await fireEvent.click(screen.getAllByRole('button', { name: 'Create…' })[1]);
    await fireEvent.input(screen.getByLabelText('Vault password'), { target: { value: 'vault pw 12345' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText('word24')).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText('Word #2'), { target: { value: 'word2' } });
    await fireEvent.input(screen.getByLabelText('Word #9'), { target: { value: 'word9' } });
    await fireEvent.input(screen.getByLabelText('Word #20'), { target: { value: 'word20' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(api.phrase_confirm).toHaveBeenCalledWith('t1', ['word2', 'word9', 'word20']));
    await waitFor(() => expect(screen.queryByText('word24')).not.toBeInTheDocument());
  });

  it('shows what replacing the phrase changed, and keeps it after the card closes', async () => {
    const NOTES = [
      'The previous recovery phrase no longer opens this vault. Backup files you exported earlier still open with the old phrase.',
      'Set up Windows Hello and camera verification again; the vault was re-encrypted under a new key.',
    ];
    fakeApi({
      backup_status: vi.fn().mockResolvedValue({ ...STATUS, phrase_enrolled: true }),
      phrase_create: vi.fn().mockResolvedValue({ ok: true, token: 't2', words: WORDS, positions: [1, 2, 3], intro: 'Write these 24 words down.', notes: NOTES }),
      phrase_close: vi.fn().mockResolvedValue({ ok: true, message: 'Recovery phrase saved.' }),
    });
    render(RecoveryPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Replace…' }));
    await fireEvent.input(screen.getByLabelText('Vault password'), { target: { value: 'vault pw 12345' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText(/previous recovery phrase no longer opens/)).toBeInTheDocument();
    expect(screen.getByText(/Set up Windows Hello and camera verification again/)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Close without confirming' }));
    await waitFor(() => expect(screen.queryByText('word24')).not.toBeInTheDocument());
    expect(screen.getByText(/previous recovery phrase no longer opens/)).toBeInTheDocument();
  });

  it('shows no notes list for a first phrase', async () => {
    fakeApi({
      backup_status: vi.fn().mockResolvedValue(STATUS),
      phrase_create: vi.fn().mockResolvedValue({ ok: true, token: 't3', words: WORDS, positions: [1, 2, 3], intro: 'Write these 24 words down.', notes: [] }),
    });
    render(RecoveryPage, { onclose: vi.fn() });
    await screen.findAllByRole('button', { name: 'Create…' });
    await fireEvent.click(screen.getAllByRole('button', { name: 'Create…' })[1]);
    await fireEvent.input(screen.getByLabelText('Vault password'), { target: { value: 'vault pw 12345' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText('word24')).toBeInTheDocument();
    expect(screen.queryByRole('list', { name: /What changed/ })).not.toBeInTheDocument();
  });
});

describe('Unlock extras', () => {
  it('shows the subtitle, status, recovery link and recovers with the phrase', async () => {
    const api = fakeApi({ vault_recover: vi.fn().mockResolvedValue({ ok: true }) });
    render(Unlock, { vault: { ...LOCKED, subtitle: 'Locked 2 minutes ago', status: 'Emergency lock. Master password required; signed-in websites/apps remain signed in.',
      recovery_phrase: true, backoff: 0, chips: [] } });
    expect(screen.getByText('Locked 2 minutes ago')).toBeInTheDocument();
    expect(screen.getByText(/Emergency lock/)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Forgot it? Use recovery phrase' }));
    await fireEvent.input(screen.getByLabelText('Recovery phrase'), { target: { value: 'a b c' } });
    await fireEvent.input(screen.getByLabelText('New master password (at least 12 characters)'), { target: { value: 'new password 12' } });
    await fireEvent.input(screen.getByLabelText('Enter the new master password again'), { target: { value: 'new password 12' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Recover vault' }));
    await waitFor(() => expect(api.vault_recover).toHaveBeenCalledWith('a b c', 'new password 12', 'new password 12'));
  });

  it('disables unlock during the backoff', () => {
    fakeApi();
    render(Unlock, { vault: { ...LOCKED, backoff: 12, chips: [] } });
    expect(screen.getByText('Too many incorrect attempts. Try again in 12 s.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Unlock' })).toBeDisabled();
  });
});

describe('MasterSheet failure', () => {
  it('clears the passwords after a refused change', async () => {
    fakeApi({ master_info: vi.fn().mockResolvedValue({ ok: true, needs_phrase: false }),
      master_change: vi.fn().mockResolvedValue({ ok: false, error: { code: 'invalid', message: 'Wrong password.' } }) });
    render(MasterSheet, { onclose: vi.fn() });
    const current = await screen.findByLabelText('Current master password');
    await fireEvent.input(current, { target: { value: 'old password 1' } });
    await fireEvent.input(screen.getByLabelText('New master password (at least 12 characters)'), { target: { value: 'new password 12' } });
    await fireEvent.input(screen.getByLabelText('Enter the new password again'), { target: { value: 'new password 12' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByText('Wrong password.')).toBeInTheDocument();
    expect(current).toHaveValue('');
    expect(screen.getByLabelText('Enter the new password again')).toHaveValue('');
  });
});
