import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import UnlockingPage from '../components/UnlockingPage.svelte';
import CameraView from '../components/CameraView.svelte';
import Unlock from './Unlock.svelte';
import { LOCKED, emit, fakeApi } from '../test/fakeApi.js';

afterEach(() => { delete window.pywebview; vi.useRealTimers(); });

const HELLO_OFF = { ok: true, supported: true, enabled: false, incomplete: false, tone: 'neutral', auto_start: true,
  status: 'Not enabled. Password entry remains the default; Windows Hello never starts automatically.', guidance: 'Windows Hello uses…' };
const FACE_OFF = { ok: true, supported: true, enabled: false, incomplete: false, tone: 'neutral',
  status: 'Not enabled. The camera starts only after you explicitly choose setup or Use camera.' };

describe('UnlockingPage', () => {
  it('enables Windows Hello and shows the result', async () => {
    const api = fakeApi({ hello_status: vi.fn().mockResolvedValue(HELLO_OFF), face_status: vi.fn().mockResolvedValue(FACE_OFF),
      hello_enable: vi.fn().mockResolvedValue({ ok: true, message: 'Windows Hello is enabled. Lock the vault and choose Windows Hello to test it.' }) });
    render(UnlockingPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Enable for this profile' }));
    await waitFor(() => expect(api.hello_enable).toHaveBeenCalled());
    expect(await screen.findByText(/Windows Hello is enabled/)).toBeInTheDocument();
  });

  it('shows a cancel notice by its code and stays quiet for a plain cancel', async () => {
    const hello_enable = vi.fn()
      .mockResolvedValueOnce({ ok: false, error: { code: 'cancelled_notice', message: 'Setup abgebrochen.' } })
      .mockResolvedValueOnce({ ok: false, error: { code: 'cancelled', message: 'Abgebrochen.' } });
    fakeApi({ hello_status: vi.fn().mockResolvedValue(HELLO_OFF), face_status: vi.fn().mockResolvedValue(FACE_OFF), hello_enable });
    render(UnlockingPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Enable for this profile' }));
    expect(await screen.findByText('Setup abgebrochen.')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Enable for this profile' }));
    await waitFor(() => expect(hello_enable).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByText('Abgebrochen.')).not.toBeInTheDocument());
  });

  it('shows the camera while camera setup runs', async () => {
    let finish;
    fakeApi({ hello_status: vi.fn().mockResolvedValue(HELLO_OFF), face_status: vi.fn().mockResolvedValue(FACE_OFF),
      face_enable: vi.fn(() => new Promise((r) => { finish = r; })) });
    render(UnlockingPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Set up camera verification' }));
    expect(await screen.findByRole('dialog', { name: 'Set up camera verification' })).toBeInTheDocument();
    finish({ ok: true, message: 'Camera verification enabled. Lock the vault and test it before relying on it.' });
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Set up camera verification' })).not.toBeInTheDocument());
  });

  it('shows the new recovery phrase once after removing camera verification replaced it', async () => {
    const words = Array.from({ length: 24 }, (_, i) => `word${i + 1}`);
    const api = fakeApi({ hello_status: vi.fn().mockResolvedValue(HELLO_OFF),
      face_status: vi.fn().mockResolvedValue({ ...FACE_OFF, enabled: true, status: 'Enabled.' }),
      face_disable: vi.fn().mockResolvedValue({ ok: true,
        message: 'Camera verification removed. Your old recovery phrase no longer works. Write down the new one shown below.',
        phrase_card: { token: 't1', words, positions: [2, 9, 17], intro: 'Write these 24 words down.',
          notes: ['The previous recovery phrase no longer opens this vault.'] } }),
      phrase_confirm: vi.fn().mockResolvedValue({ ok: true, confirmed: true, message: 'Recovery phrase confirmed.' }) });
    render(UnlockingPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Remove' }));
    expect(await screen.findByText(/Your old recovery phrase no longer works/)).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Your recovery phrase' })).toBeInTheDocument();
    expect(screen.getByText('word24')).toBeInTheDocument();
    expect(screen.getByText('The previous recovery phrase no longer opens this vault.')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(api.phrase_confirm).toHaveBeenCalledWith('t1', ['', '', '']));
    expect(await screen.findByText('Recovery phrase confirmed.')).toBeInTheDocument();
    expect(screen.queryByText('word24')).not.toBeInTheDocument();
  });
});

describe('CameraView', () => {
  it('follows status and frame events and cancels through Python', async () => {
    const api = fakeApi({ face_cancel: vi.fn().mockResolvedValue({ ok: true }) });
    render(CameraView, { title: 'Camera verification', mode: 'verify' });
    emit('face.status', { status: 'Face not recognised', detail: 'Try better lighting, or use your master password.', progress: 0, state: 'running' });
    expect(await screen.findByText('Face not recognised')).toBeInTheDocument();
    emit('face.frame', { image: 'data:image/jpeg;base64,AAAA', progress: 0.5 });
    await waitFor(() => expect(document.querySelector('img')).toHaveAttribute('src', 'data:image/jpeg;base64,AAAA'));
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(api.face_cancel).toHaveBeenCalled();
  });
});

describe('Unlock with Windows Hello and camera', () => {
  it('auto-starts Windows Hello once when offered', async () => {
    const api = fakeApi({ vault_unlock_hello: vi.fn().mockResolvedValue({ ok: false, error: { code: 'cancelled', message: 'Unlock cancelled. Try again or use your master password.' } }) });
    render(Unlock, { vault: { ...LOCKED, hello: true, hello_auto: true, camera: false, chips: [], backoff: 0 } });
    await waitFor(() => expect(api.vault_unlock_hello).toHaveBeenCalledTimes(1));
    expect(await screen.findByText('Unlock cancelled. Try again or use your master password.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Unlock with Windows Hello' })).toBeInTheDocument();
  });

  it('hides Hello and the camera when they are not offered', () => {
    fakeApi();
    render(Unlock, { vault: { ...LOCKED, hello: false, camera: false, chips: [], backoff: 0 } });
    expect(screen.queryByRole('button', { name: 'Unlock with Windows Hello' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Use camera instead' })).not.toBeInTheDocument();
  });

  it('runs the camera check from the link', async () => {
    let finish;
    const api = fakeApi({ vault_unlock_face: vi.fn(() => new Promise((r) => { finish = r; })) });
    render(Unlock, { vault: { ...LOCKED, hello: false, camera: true, chips: [], backoff: 0 } });
    await fireEvent.click(screen.getByRole('button', { name: 'Use camera instead' }));
    expect(api.vault_unlock_face).toHaveBeenCalled();
    expect(await screen.findByRole('dialog', { name: 'Camera verification' })).toBeInTheDocument();
    finish({ ok: false, error: { code: 'face_failed', message: 'Face not recognised in time.' } });
    expect(await screen.findByText('Face not recognised in time.')).toBeInTheDocument();
  });
});

describe('Security key', () => {
  it('unlocks with the security key when offered and shows its error', async () => {
    const api = fakeApi({ vault_unlock_security_key: vi.fn().mockResolvedValue({ ok: false, error: { code: 'security_key_failed', message: 'This is not the security key set up for this profile.' } }) });
    render(Unlock, { vault: { ...LOCKED, hello: false, security_key: true, camera: false, chips: [], backoff: 0 } });
    await fireEvent.click(screen.getByRole('button', { name: 'Unlock with security key' }));
    expect(api.vault_unlock_security_key).toHaveBeenCalledTimes(1);
    expect(await screen.findByText('This is not the security key set up for this profile.')).toBeInTheDocument();
  });

  it('is not shown when not offered', () => {
    fakeApi();
    render(Unlock, { vault: { ...LOCKED, hello: false, security_key: false, camera: false, chips: [], backoff: 0 } });
    expect(screen.queryByRole('button', { name: 'Unlock with security key' })).not.toBeInTheDocument();
  });

  it('sets up a security key from the Unlocking page', async () => {
    const security_key_enable = vi.fn().mockResolvedValue({ ok: true, message: 'Security key unlock is enabled.' });
    fakeApi({ hello_status: vi.fn().mockResolvedValue(HELLO_OFF), face_status: vi.fn().mockResolvedValue(FACE_OFF),
      security_key_status: vi.fn().mockResolvedValue({ ok: true, supported: true, enabled: false, incomplete: false, tone: 'neutral', status: 'Not set up.', guidance: 'Use a FIDO2 key.' }),
      security_key_enable });
    render(UnlockingPage, { onclose: () => {} });
    await fireEvent.click(await screen.findByRole('button', { name: 'Set up a security key' }));
    expect(security_key_enable).toHaveBeenCalled();
    expect(await screen.findByText('Security key unlock is enabled.')).toBeInTheDocument();
  });

  it('shows why a security key cannot be used', async () => {
    fakeApi({ hello_status: vi.fn().mockResolvedValue(HELLO_OFF), face_status: vi.fn().mockResolvedValue(FACE_OFF),
      security_key_status: vi.fn().mockResolvedValue({ ok: true, supported: false, enabled: false, incomplete: false, tone: 'neutral', status: 'Windows is too old (version 3).', guidance: 'Use a FIDO2 key.' }) });
    render(UnlockingPage, { onclose: () => {} });
    expect(await screen.findByText('Windows is too old (version 3).')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Set up a security key' })).not.toBeInTheDocument();
  });
});

describe('Key file and YubiKey on the Unlocking page', () => {
  const STATUS = { ok: true, factors: [], keyfile_name: null, remember: true, always_ask: false, shortcuts_off: false,
    hint: 'A key file or YubiKey is then needed.', yubikey_setup: 'Set it up in Yubico Authenticator.' };

  it('adds a YubiKey on the chosen slot and a key file', async () => {
    const factors_add_yubikey = vi.fn().mockResolvedValue({ ok: true, message: 'YubiKey added (slot 1).' });
    const factors_add_keyfile = vi.fn().mockResolvedValue({ ok: true, message: 'Key file vault.keyx added.' });
    fakeApi({ hello_status: vi.fn().mockResolvedValue(HELLO_OFF), face_status: vi.fn().mockResolvedValue(FACE_OFF),
      factors_status: vi.fn().mockResolvedValue(STATUS), factors_add_yubikey, factors_add_keyfile });
    render(UnlockingPage, { onclose: vi.fn() });
    expect(await screen.findByText('Set it up in Yubico Authenticator.')).toBeInTheDocument();
    await fireEvent.change(screen.getByLabelText('Slot'), { target: { value: '1' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Add YubiKey' }));
    await waitFor(() => expect(factors_add_yubikey).toHaveBeenCalledWith(1));
    expect(await screen.findByText('YubiKey added (slot 1).')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Add key file…' }));
    await waitFor(() => expect(factors_add_keyfile).toHaveBeenCalled());
  });

  it('checks a backup YubiKey with its own call', async () => {
    const factors_check_backup_yubikey = vi.fn().mockResolvedValue({ ok: true, message: 'This YubiKey gives the same answer.' });
    fakeApi({ hello_status: vi.fn().mockResolvedValue(HELLO_OFF), face_status: vi.fn().mockResolvedValue(FACE_OFF),
      factors_status: vi.fn().mockResolvedValue({ ...STATUS, factors: [{ kind: 'yubikey-hmac', slot: 2 }] }),
      factors_check_backup_yubikey });
    render(UnlockingPage, { onclose: vi.fn() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Check a backup YubiKey' }));
    await waitFor(() => expect(factors_check_backup_yubikey).toHaveBeenCalledWith());
    expect(await screen.findByText('This YubiKey gives the same answer.')).toBeInTheDocument();
  });

  it('turns on "Always ask" and then hides the Hello, security key and camera setup', async () => {
    const set = [{ kind: 'keyfile', slot: null }];
    const factors_status = vi.fn().mockResolvedValueOnce({ ...STATUS, factors: set, keyfile_name: 'vault.keyx' })
      .mockResolvedValue({ ...STATUS, factors: set, keyfile_name: 'vault.keyx', always_ask: true, shortcuts_off: true });
    const factors_set_always_ask = vi.fn().mockResolvedValue({ ok: true, always_ask: true,
      message: 'The key file / YubiKey is now asked at every unlock. Windows Hello removed.' });
    fakeApi({ hello_status: vi.fn().mockResolvedValue(HELLO_OFF), face_status: vi.fn().mockResolvedValue(FACE_OFF),
      factors_status, factors_set_always_ask });
    render(UnlockingPage, { onclose: vi.fn() });
    expect(await screen.findByText(/vault\.keyx/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Enable for this profile' })).toBeInTheDocument();
    await fireEvent.click(screen.getByLabelText('Always ask for the key file / YubiKey'));
    await waitFor(() => expect(factors_set_always_ask).toHaveBeenCalledWith(true));
    expect(await screen.findByText(/now asked at every unlock/)).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Enable for this profile' })).not.toBeInTheDocument());
    expect(screen.getByText(/are off while/)).toBeInTheDocument();
  });
});
