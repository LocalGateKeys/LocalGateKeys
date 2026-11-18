import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import PasskeyDoctorPage from '../components/PasskeyDoctorPage.svelte';
import { fakeApi } from '../test/fakeApi.js';

afterEach(() => cleanup());

describe('PasskeyDoctorPage', () => {
  it('shows the checks and browsers and opens the Windows settings', async () => {
    const open = vi.fn().mockResolvedValue({ ok: true });
    fakeApi({
      passkey_doctor_view: vi.fn().mockResolvedValue({ ok: true, provider: { code: 'not_active', text: 'Provider line' },
        checks: [{ key: 'host', ok: false, label: 'Host check', detail: 'Missing' }],
        browsers: [{ browser: 'Edge', ok: true, state: 'Connected' }], note: 'Read only' }),
      passkey_doctor_open_settings: open,
    });
    render(PasskeyDoctorPage, { onclose: () => {} });
    await waitFor(() => expect(screen.getByText('● Provider line')).toBeTruthy());
    expect(screen.getByText('Host check')).toBeTruthy();
    expect(screen.getByText('Edge')).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: /windows/i }));
    expect(open).toHaveBeenCalled();
  });
});

import Generator from '../components/Generator.svelte';

describe('Generator clipboard countdown', () => {
  it('counts down after a copy when auto-clear is on', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    fakeApi({
      generator_get: vi.fn().mockResolvedValue({ ok: true, options: {} }),
      generator_generate: vi.fn().mockResolvedValue({ ok: true, value: 'pw', health: '', options: {} }),
      generator_copy: vi.fn().mockResolvedValue({ ok: true, message: 'Copied', clear_seconds: 3 }),
    });
    render(Generator, { onclose: () => {} });
    await fireEvent.click(await screen.findByRole('button', { name: /copy/i }));
    await waitFor(() => expect(screen.getByRole('status').textContent).toMatch(/3/));
    await vi.advanceTimersByTimeAsync(1000);
    await waitFor(() => expect(screen.getByRole('status').textContent).toMatch(/2/));
    await vi.advanceTimersByTimeAsync(3000);
    await waitFor(() => expect(screen.queryByRole('status')).toBeNull());
    vi.useRealTimers();
  });
});
