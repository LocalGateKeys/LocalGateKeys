import { afterEach, describe, expect, it, vi } from 'vitest';
import { call, on } from './api.js';

afterEach(() => {
  delete window.pywebview;
});

describe('api.call', () => {
  it('calls the bridge method and returns its result', async () => {
    window.pywebview = { api: { vault_state: vi.fn().mockResolvedValue({ ok: true, state: 'locked' }) } };
    await expect(call('vault_state')).resolves.toEqual({ ok: true, state: 'locked' });
  });

  it('waits for pywebviewready when the bridge is not there yet', async () => {
    const pending = call('vault_unlock', 'pw');
    window.pywebview = { api: { vault_unlock: vi.fn().mockResolvedValue({ ok: true }) } };
    window.dispatchEvent(new Event('pywebviewready'));
    await expect(pending).resolves.toEqual({ ok: true });
    expect(window.pywebview.api.vault_unlock).toHaveBeenCalledWith('pw');
  });

  it('turns a bridge exception into a failure result', async () => {
    window.pywebview = { api: { vault_lock: vi.fn().mockRejectedValue(new Error('gone')) } };
    const result = await call('vault_lock');
    expect(result.ok).toBe(false);
    expect(result.error.code).toBe('bridge');
  });
});

describe('api.on', () => {
  it('receives lgk events by name and can unsubscribe', () => {
    const seen = [];
    const off = on('vault.state', (detail) => seen.push(detail.state));
    window.dispatchEvent(new CustomEvent('lgk', { detail: { name: 'vault.state', detail: { state: 'unlocked' } } }));
    window.dispatchEvent(new CustomEvent('lgk', { detail: { name: 'toast', detail: {} } }));
    off();
    window.dispatchEvent(new CustomEvent('lgk', { detail: { name: 'vault.state', detail: { state: 'locked' } } }));
    expect(seen).toEqual(['unlocked']);
  });
});
