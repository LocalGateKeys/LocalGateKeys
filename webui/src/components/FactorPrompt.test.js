import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import FactorPrompt from './FactorPrompt.svelte';
import { emit, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; });

const KEYFILE = [{ kind: 'keyfile', slot: null }];
const YUBIKEY = [{ kind: 'yubikey-hmac', slot: 1 }];

describe('FactorPrompt', () => {
  it('shows the remembered key file and picks another one', async () => {
    const api = fakeApi({ factors_pick_keyfile: vi.fn().mockResolvedValue({ ok: true, name: 'other.keyx' }) });
    render(FactorPrompt, { factors: KEYFILE, keyfileName: 'vault.keyx', remember: true });
    expect(screen.getByText('Key file: vault.keyx')).toBeInTheDocument();
    expect(screen.getByLabelText('Remember this key file on this PC')).toBeChecked();
    await fireEvent.click(screen.getByRole('button', { name: 'Choose key file…' }));
    expect(api.factors_pick_keyfile).toHaveBeenCalled();
    expect(await screen.findByText('Key file: other.keyx')).toBeInTheDocument();
  });

  it('says no key file is chosen and turns remembering off', async () => {
    const api = fakeApi({ factors_set_remember: vi.fn().mockResolvedValue({ ok: true, remember: false }) });
    render(FactorPrompt, { factors: KEYFILE, keyfileName: null, remember: true });
    expect(screen.getByText('No key file chosen')).toBeInTheDocument();
    await fireEvent.click(screen.getByLabelText('Remember this key file on this PC'));
    await waitFor(() => expect(api.factors_set_remember).toHaveBeenCalledWith(false));
    await waitFor(() => expect(screen.getByLabelText('Remember this key file on this PC')).not.toBeChecked());
  });

  it('names the YubiKey slot, then shows the touch state with a working Cancel', async () => {
    const api = fakeApi({ factors_cancel: vi.fn().mockResolvedValue({ ok: true }) });
    render(FactorPrompt, { factors: YUBIKEY });
    expect(screen.getByText('Insert your YubiKey (slot 1) and touch it when it blinks.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Choose key file…' })).not.toBeInTheDocument();
    emit('factors.touch', { waiting: true, slot: 1 });
    expect(await screen.findByText('Touch your YubiKey')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(api.factors_cancel).toHaveBeenCalled();
    emit('factors.touch_again', { slot: 1 });
    expect(await screen.findByText('Touch your YubiKey again to confirm')).toBeInTheDocument();
    emit('factors.touch', { waiting: false, slot: 1 });
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument());
  });
});
