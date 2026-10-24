import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import DesktopSheet from '../components/DesktopSheet.svelte';
import { fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const SCAN = { ok: true, token: 't1', app: 'app.exe', title: 'Example sign in', current: 'Not mapped',
  buttons: [{ index: 5, name: 'Sign in' }, { index: 6, name: 'Cancel' }] };

describe('DesktopSheet sign-in button', () => {
  it('lists the app buttons and saves the chosen one', async () => {
    const api = fakeApi({ desktop_signin_scan: vi.fn().mockResolvedValue(SCAN),
      desktop_signin_save: vi.fn().mockResolvedValue({ ok: true, message: 'Sign-in button Sign in saved.' }) });
    render(DesktopSheet, { entryId: 'd1', onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Map sign-in button…' }));
    expect(api.desktop_signin_scan).toHaveBeenCalledWith('d1');
    expect(await screen.findByText(/Sign-in button now: Not mapped/)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(api.desktop_signin_save).toHaveBeenCalledWith('t1', 5));
    await waitFor(() => expect(screen.queryByRole('group', { name: 'Buttons in the app' })).not.toBeInTheDocument());
  });

  it('shows a refusal (name not unique) and keeps the list', async () => {
    fakeApi({ desktop_signin_scan: vi.fn().mockResolvedValue(SCAN),
      desktop_signin_save: vi.fn().mockResolvedValue({ ok: false, error: { code: 'refused', message: 'That name is not unique.' } }) });
    render(DesktopSheet, { entryId: 'd1', onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Map sign-in button…' }));
    await fireEvent.click(await screen.findByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('That name is not unique.');
    expect(screen.getByRole('group', { name: 'Buttons in the app' })).toBeInTheDocument();
  });

  it('asks for the embedded-web warning again', async () => {
    const api = fakeApi({ desktop_web_warning_reset: vi.fn().mockResolvedValue({ ok: true, message: 'ok' }) });
    render(DesktopSheet, { entryId: 'd1', onclose: vi.fn() });
    await fireEvent.click(screen.getByRole('button', { name: 'Require web warning again' }));
    expect(api.desktop_web_warning_reset).toHaveBeenCalledWith('d1');
  });
});
