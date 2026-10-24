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
