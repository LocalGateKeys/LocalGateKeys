import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { tick } from 'svelte';
import EmergencyKit from './EmergencyKit.svelte';
import PhraseCard from './PhraseCard.svelte';
import { fakeApi } from '../test/fakeApi.js';

const FACTS = { profile: 'Alex', vault_path: 'C:\\Users\\a\\vault.json', backup_folders: ['D:\\Backups'],
  created: '2026-11-03', app_version: '0.4.10' };
const WORDS = Array.from({ length: 24 }, (_, i) => `word${i + 1}`);

afterEach(() => {
  vi.restoreAllMocks();
  delete window.pywebview;
  document.querySelectorAll('.kit-portal').forEach((n) => n.remove());
});

const boxes = () => [...document.querySelectorAll('[data-testid="kit-box"]')];
const frames = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r())));
const flush = async () => { await tick(); await frames(); await tick(); };

describe('emergency kit', () => {
  it('test_kit_without_phrase_has_blank_boxes', async () => {
    vi.spyOn(window, 'print').mockImplementation(() => {});
    render(EmergencyKit, { facts: FACTS, words: null, ondone: () => {} });
    await flush();
    expect(boxes()).toHaveLength(24);
    expect(boxes().every((b) => b.querySelector('[data-word]').textContent === '')).toBe(true);
    expect(document.body.textContent).toContain('Alex');
    expect(document.body.textContent).toContain('D:\\Backups');
  });

  it('has no holder page without an emergency access plan', async () => {
    vi.spyOn(window, 'print').mockImplementation(() => {});
    render(EmergencyKit, { facts: FACTS, words: null, ondone: () => {} });
    await flush();
    expect(document.querySelector('[data-testid="kit-holders"]')).toBeNull();
  });

  it('lists the emergency access holders by nickname on their own page', async () => {
    vi.spyOn(window, 'print').mockImplementation(() => {});
    render(EmergencyKit, { facts: { ...FACTS, heir_holders: ['Mum', 'Kostas'] }, words: null, ondone: () => {} });
    await flush();
    const page = document.querySelector('[data-testid="kit-holders"]');
    expect([...page.querySelectorAll('li')].map((li) => li.textContent)).toEqual(['Mum', 'Kostas']);
  });

  it('test_kit_with_phrase_fills_boxes', async () => {
    vi.spyOn(window, 'print').mockImplementation(() => {});
    render(EmergencyKit, { facts: FACTS, words: WORDS, ondone: () => {} });
    await flush();
    expect(boxes().map((b) => b.querySelector('[data-word]').textContent)).toEqual(WORDS);
  });

  it('test_print_calls_window_print', async () => {
    const print = vi.spyOn(window, 'print').mockImplementation(() => {});
    const ondone = vi.fn();
    render(EmergencyKit, { facts: FACTS, words: WORDS, ondone });
    await flush();
    expect(print).toHaveBeenCalledTimes(1);
    expect(ondone).not.toHaveBeenCalled();
    window.dispatchEvent(new Event('afterprint'));
    expect(ondone).toHaveBeenCalledTimes(1);
    window.dispatchEvent(new Event('afterprint'));
    expect(ondone).toHaveBeenCalledTimes(1);
  });

  it('clears after the fallback timer when afterprint never arrives', async () => {
    vi.useFakeTimers();
    try {
      const print = vi.spyOn(window, 'print').mockImplementation(() => {});
      const ondone = vi.fn();
      render(EmergencyKit, { facts: FACTS, words: WORDS, ondone });
      await vi.advanceTimersByTimeAsync(100);
      expect(print).toHaveBeenCalledTimes(1);
      expect(ondone).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
      expect(ondone).toHaveBeenCalledTimes(1);
    } finally { vi.useRealTimers(); }
  });

  it('is cleared at once when print throws', async () => {
    vi.spyOn(window, 'print').mockImplementation(() => { throw new Error('no dialog'); });
    const ondone = vi.fn();
    render(EmergencyKit, { facts: FACTS, words: WORDS, ondone });
    await flush();
    expect(ondone).toHaveBeenCalledTimes(1);
  });

  it('prints from the phrase card with the facts call carrying no words, once even on a double click', async () => {
    vi.spyOn(window, 'print').mockImplementation(() => {});
    const api = fakeApi({ recovery_kit_facts: vi.fn().mockResolvedValue({ ok: true, ...FACTS }) });
    render(PhraseCard, { card: { token: 't', intro: 'x', words: WORDS, positions: [1, 2, 3] }, ondone: () => {} });
    const button = screen.getByRole('button', { name: 'Print kit with this phrase…' });
    await fireEvent.click(button);
    await fireEvent.click(button);
    await waitFor(() => expect(boxes()).toHaveLength(24));
    expect(api.recovery_kit_facts).toHaveBeenCalledTimes(1);
    expect(api.recovery_kit_facts.mock.calls[0]).toEqual([]);
    expect(boxes().map((b) => b.querySelector('[data-word]').textContent)).toEqual(WORDS);
    expect(document.querySelectorAll('.kit-portal')).toHaveLength(1);
  });
});
