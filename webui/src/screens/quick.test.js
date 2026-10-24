import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import QuickAccess from '../components/QuickAccess.svelte';
import ChoiceModal from '../components/ChoiceModal.svelte';
import { fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const ROWS = [{ ref: { source: 'credential', id: 'a', kind: 'web' }, title: '★ Beta', subtitle: 'bob' },
  { ref: { source: 'typed', id: 'n', kind: 'note' }, title: 'Router', subtitle: 'Secure note' }];

describe('QuickAccess', () => {
  it('searches as you type and opens the picked row', async () => {
    const api = fakeApi({ quick_search: vi.fn().mockResolvedValue({ ok: true, rows: ROWS, profile: 'Personal' }) });
    const onopen = vi.fn();
    render(QuickAccess, { onclose: vi.fn(), onopen });
    expect(await screen.findByText(/Profile: Personal/)).toBeInTheDocument();
    await fireEvent.input(screen.getByPlaceholderText('Find a login, note or bookmark'), { target: { value: 'rou' } });
    await waitFor(() => expect(api.quick_search).toHaveBeenLastCalledWith('rou', ''));
    await fireEvent.click(screen.getByRole('option', { name: /Router/ }));
    expect(onopen).toHaveBeenCalledWith(ROWS[1].ref);
  });

  it('closes on Escape', async () => {
    fakeApi({ quick_search: vi.fn().mockResolvedValue({ ok: true, rows: [], profile: 'P' }) });
    const onclose = vi.fn();
    render(QuickAccess, { onclose, onopen: vi.fn() });
    await screen.findByText('No matches.');
    await fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(onclose).toHaveBeenCalled();
  });
});

describe('ChoiceModal', () => {
  it('returns the chosen account id', async () => {
    const onanswer = vi.fn();
    render(ChoiceModal, { request: { kind: 'choose', title: 'Choose an account', message: '',
      options: [{ id: 'x', label: 'ann' }, { id: 'y', label: 'bob' }] }, onanswer });
    expect(screen.getByRole('button', { name: 'Use this account' })).toBeDisabled();
    await fireEvent.click(screen.getByLabelText('bob'));
    await fireEvent.click(screen.getByRole('button', { name: 'Use this account' }));
    expect(onanswer).toHaveBeenCalledWith('y');
  });

  it('confirms with the remember box, and cancel is not approved', async () => {
    const onanswer = vi.fn();
    render(ChoiceModal, { request: { kind: 'confirm_remember', title: 'Fill app?', message: 'm', remember_label: 'Remember' }, onanswer });
    await fireEvent.click(screen.getByLabelText('Remember'));
    await fireEvent.click(screen.getByRole('button', { name: 'Fill' }));
    expect(onanswer).toHaveBeenLastCalledWith({ approved: true, remember: true });
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onanswer).toHaveBeenLastCalledWith({ approved: false, remember: false });
  });
});
