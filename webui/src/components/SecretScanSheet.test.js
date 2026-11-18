import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import SecretScanSheet from './SecretScanSheet.svelte';
import DeveloperPage from './DeveloperPage.svelte';
import { emit, fakeApi } from '../test/fakeApi.js';

const ROWS = [
  { id: 'f1', name: 'id_ed25519', folder: 'C:\\Users\\a\\.ssh', path: 'C:\\Users\\a\\.ssh\\id_ed25519', kind: 'ssh_private_key', var_count: 0, key_format: 'openssh', imported: false },
  { id: 'f2', name: '.env', folder: 'C:\\code\\app', path: 'C:\\code\\app\\.env', kind: 'env_file', var_count: 3, key_format: null, imported: false },
];
const PREVIEW = { ok: true, token: 'tok', path: 'C:\\code\\app\\.env', cli_enabled: false, rewrite_count: 1, skip_count: 1, rows: [
  { line: 2, name: 'STRIPE_KEY', action: 'rewrite', before: '••••••', after: 'lgk://abc/STRIPE_KEY' },
  { line: 4, name: 'PORT', action: 'skip', reason: 'comment' },
] };

afterEach(() => {
  vi.restoreAllMocks();
  delete window.pywebview;
});

function mount(overrides = {}, onclose = () => {}) {
  const api = fakeApi({
    secret_scan_start: vi.fn().mockResolvedValue({ ok: true, job: 'secret_scan' }),
    secret_scan_cancel: vi.fn().mockResolvedValue({ ok: true }),
    secret_scan_choose_folder: vi.fn().mockResolvedValue({ ok: true, folder: 'D:\\work' }),
    secret_scan_import: vi.fn().mockResolvedValue({ ok: true, imported: ['f2'], failed: 0, message: 'Imported: 1.',
      rows: [ROWS[0], { ...ROWS[1], imported: true }] }),
    secret_scan_rewrite_preview: vi.fn().mockResolvedValue(PREVIEW),
    secret_scan_rewrite_apply: vi.fn().mockResolvedValue({ ok: true, rewritten: 1, message: 'Values replaced: 1.', cli_enabled: false,
      rows: [ROWS[0]] }),
    ...overrides,
  });
  render(SecretScanSheet, { onclose, cliEnabled: false });
  return api;
}

async function finishScan(rows = ROWS) {
  await fireEvent.click(screen.getByRole('button', { name: 'Scan' }));
  emit('job.done', { job: 'secret_scan', ok: true, message: `Plain secrets found: ${rows.length}.`, rows });
}

describe('secret scan sheet', () => {
  it('test_scan_with_the_default_folder_then_lists_results_without_values', async () => {
    const api = mount();
    expect(screen.getByText('Your user folder')).toBeTruthy();
    await finishScan();
    await waitFor(() => expect(api.secret_scan_start).toHaveBeenCalledWith(null));
    expect(await screen.findByText('id_ed25519')).toBeTruthy();
    expect(screen.getByText(/Variables: 3/)).toBeTruthy();
    expect(screen.getByText('SSH private key')).toBeTruthy();
    expect(screen.getByText('C:\\code\\app')).toBeTruthy();
  });

  it('test_progress_is_shown_and_stop_cancels', async () => {
    const api = mount();
    await fireEvent.click(screen.getByRole('button', { name: 'Scan' }));
    emit('job.progress', { job: 'secret_scan', text: 'Looked at 200 files…' });
    expect((await screen.findByRole('status')).textContent).toBe('Looked at 200 files…');
    await fireEvent.click(screen.getByRole('button', { name: 'Stop' }));
    await waitFor(() => expect(api.secret_scan_cancel).toHaveBeenCalled());
  });

  it('test_added_folders_replace_the_default', async () => {
    const api = mount();
    await fireEvent.click(screen.getByRole('button', { name: 'Add folder' }));
    expect(await screen.findByText('D:\\work')).toBeTruthy();
    expect(screen.queryByText('Your user folder')).toBeNull();
    await finishScan([]);
    await waitFor(() => expect(api.secret_scan_start).toHaveBeenCalledWith(['D:\\work']));
    expect(await screen.findByText('No plain secrets found.')).toBeTruthy();
  });

  it('test_import_sends_only_the_ticked_rows', async () => {
    const api = mount();
    await finishScan();
    const importButton = await screen.findByRole('button', { name: 'Import selected' });
    expect(importButton.disabled).toBe(true);
    await fireEvent.click(screen.getByRole('checkbox', { name: 'Select C:\\code\\app\\.env' }));
    await fireEvent.click(importButton);
    await waitFor(() => expect(api.secret_scan_import).toHaveBeenCalledWith(['f2']));
    expect(await screen.findByText('In your vault')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Use references' })).toBeTruthy();
  });

  it('test_rewrite_shows_a_preview_and_writes_only_after_confirm', async () => {
    const api = mount();
    await finishScan();
    await fireEvent.click(await screen.findByRole('checkbox', { name: 'Select C:\\code\\app\\.env' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Import selected' }));
    await fireEvent.click(await screen.findByRole('button', { name: 'Use references' }));
    const dialog = await screen.findByRole('dialog', { name: 'Replace values with references?' });
    expect(api.secret_scan_rewrite_preview).toHaveBeenCalledWith('f2');
    expect(dialog.textContent).toContain('lgk://abc/STRIPE_KEY');
    expect(dialog.textContent).toContain('a comment follows the value');
    expect(api.secret_scan_rewrite_apply).not.toHaveBeenCalled();
    await fireEvent.click(screen.getByRole('button', { name: 'Rewrite file' }));
    await waitFor(() => expect(api.secret_scan_rewrite_apply).toHaveBeenCalledWith('f2', 'tok'));
    expect(screen.queryByRole('dialog', { name: 'Replace values with references?' })).toBeNull();
    expect(await screen.findByRole('note')).toBeTruthy();
  });

  it('test_rewrite_cancel_changes_nothing', async () => {
    const api = mount();
    await finishScan();
    await fireEvent.click(await screen.findByRole('checkbox', { name: 'Select C:\\code\\app\\.env' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Import selected' }));
    await fireEvent.click(await screen.findByRole('button', { name: 'Use references' }));
    await screen.findByRole('dialog', { name: 'Replace values with references?' });
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog', { name: 'Replace values with references?' })).toBeNull();
    expect(api.secret_scan_rewrite_apply).not.toHaveBeenCalled();
  });

  it('test_developer_page_opens_the_scan_sheet', async () => {
    fakeApi({
      developer_status: vi.fn().mockResolvedValue({ ok: true, agent: { enabled: false, status: 'off' }, keys: [],
        env: { name: 'SSH_AUTH_SOCK', current: '', pipe: 'p', applied: false },
        git: { available: true, signing_ok: true, version: '2.50', applied: false }, cli: { enabled: true, items: [] } }),
      secret_scan_cancel: vi.fn().mockResolvedValue({ ok: true }),
    });
    render(DeveloperPage, { onclose: () => {} });
    await fireEvent.click(await screen.findByRole('button', { name: 'Scan…' }));
    expect(await screen.findByRole('dialog', { name: 'Plain secrets on this PC' })).toBeTruthy();
  });

  it('test_escape_closes_the_preview_first_then_the_sheet', async () => {
    const onclose = vi.fn();
    mount({}, onclose);
    await finishScan();
    await fireEvent.click(await screen.findByRole('checkbox', { name: 'Select C:\\code\\app\\.env' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Import selected' }));
    await fireEvent.click(await screen.findByRole('button', { name: 'Use references' }));
    await screen.findByRole('dialog', { name: 'Replace values with references?' });
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.queryByRole('dialog', { name: 'Replace values with references?' })).toBeNull();
    expect(onclose).not.toHaveBeenCalled();
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(onclose).toHaveBeenCalledTimes(1);
  });
});
