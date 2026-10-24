import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import ImportSheet from '../components/ImportSheet.svelte';
import ExportSheet from '../components/ExportSheet.svelte';
import TransferSheet from '../components/TransferSheet.svelte';
import { fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const REVIEW = { ok: true, handle: 'h1', subtitle: 'chrome.csv · 2 records.', summary: 'Add 2 · Replace 0 · Merge 0 · Keep both 0 · Skip 0 of 2',
  diagnostics: [], applying: false,
  rows: [{ row: 1, name: 'Site0', website: 'site0.test', username: 'u0', kind: 'Website login', status: 'new', decision: 'add' }] };

describe('ImportSheet', () => {
  it('maps columns, reviews and applies', async () => {
    const api = fakeApi({
      import_open: vi.fn().mockResolvedValue({ ok: true, handle: 'h1', label: 'CSV', needs_password: false, password_text: '',
        mapping: { subtitle: 'CSV: 3 columns, 1 rows.', none: '(not imported)', unmapped: 'Not recognised automatically: Col A',
          columns: ['Col A', 'Col C'], targets: [{ key: 'title', label: 'Name', value: '' }, { key: 'password', label: 'Password', value: '' }] } }),
      import_plan: vi.fn().mockResolvedValue(REVIEW),
      import_apply: vi.fn().mockResolvedValue({ ok: true, title: 'Import complete', message: '1 record(s) written.', status: 'Imported 1 record(s).' }),
      import_close: vi.fn().mockResolvedValue({ ok: true }),
    });
    const onclose = vi.fn();
    render(ImportSheet, { onclose });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    await fireEvent.change(await screen.findByLabelText('Password'), { target: { value: 'Col C' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(api.import_plan).toHaveBeenCalledWith('h1', null, { title: '', password: 'Col C' }));
    expect(await screen.findByText(REVIEW.summary)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    await waitFor(() => expect(onclose).toHaveBeenCalled());
  });

  it('asks again after a wrong source password', async () => {
    fakeApi({
      import_open: vi.fn().mockResolvedValue({ ok: true, handle: 'h2', label: 'KeePass', needs_password: true, password_text: 'KeePass is encrypted.', mapping: null }),
      import_plan: vi.fn().mockResolvedValue({ ok: false, error: { code: 'wrong_password', message: 'Wrong password.\nTry the password again.' } }),
      import_close: vi.fn().mockResolvedValue({ ok: true }),
    });
    render(ImportSheet, { onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    await fireEvent.input(await screen.findByLabelText('Import password'), { target: { value: 'nope' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Try the password again.');
    expect(screen.getByLabelText('Import password')).toHaveValue('');
  });
});

describe('ExportSheet', () => {
  it('shows warnings for the format and exports', async () => {
    const api = fakeApi({
      export_formats: vi.fn().mockResolvedValue({ ok: true, intro: 'Writes a copy.', min_password: 12,
        formats: [{ key: 'kdbx', label: 'KeePass (.kdbx)' }, { key: 'csv', label: 'CSV' }], warnings: ['The .kdbx file is encrypted.'] }),
      export_run: vi.fn().mockResolvedValue({ ok: true, title: 'Export complete', message: 'done', status: 'Exported 1 record(s).' }),
    });
    const onclose = vi.fn();
    render(ExportSheet, { onclose });
    expect(await screen.findByText('The .kdbx file is encrypted.')).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText('KDBX password (at least 12 characters)'), { target: { value: 'kdbx password 123' } });
    await fireEvent.input(screen.getByLabelText('Repeat the KDBX password'), { target: { value: 'kdbx password 123' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Export' }));
    await waitFor(() => expect(api.export_run).toHaveBeenCalledWith('kdbx', false, 'kdbx password 123', 'kdbx password 123'));
    await waitFor(() => expect(onclose).toHaveBeenCalled());
  });
});

describe('TransferSheet', () => {
  it('commits only after a preview', async () => {
    const api = fakeApi({
      transfer_info: vi.fn().mockResolvedValue({ ok: true, title: 'Encrypted transfer · Local-only', intro: 'Preview first.', scope_note: 'Use IDs.', policies: ['skip', 'copy', 'replace'], status: 'Ready.' }),
      transfer_choose: vi.fn().mockResolvedValue({ ok: true, handle: 'p1', path: 'C:\\pkg.lgt' }),
      transfer_preview: vi.fn().mockResolvedValue({ ok: true, token: 't1', lines: ['Records: 1 (0 items, 1 credentials)'], status: 'Preview is ready.' }),
      transfer_commit: vi.fn().mockResolvedValue({ ok: true, lines: ['Records: 1'], status: 'Transfer complete.' }),
      transfer_cancel: vi.fn().mockResolvedValue({ ok: true }),
    });
    render(TransferSheet, { onclose: vi.fn() });
    const write = await screen.findByRole('button', { name: 'Write package' });
    expect(write).toBeDisabled();
    await fireEvent.click(screen.getByRole('button', { name: 'Choose…' }));
    await fireEvent.input(screen.getByLabelText('Transfer password'), { target: { value: 'transfer pw 123' } });
    await fireEvent.input(screen.getByLabelText('Confirm password (export)'), { target: { value: 'transfer pw 123' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
    expect(await screen.findByText(/Records: 1 \(0 items/)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Write package' }));
    await waitFor(() => expect(api.transfer_commit).toHaveBeenCalled());
    expect(api.transfer_commit.mock.calls[0][0]).toBe('t1');
  });
});
