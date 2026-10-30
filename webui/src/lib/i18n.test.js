import { describe, it, expect, beforeEach, vi } from 'vitest';
import en from '../../../src/localvault/assets/i18n/en.json';
import { t, setMessages, lang, loadLocale, formatNumber, formatDate } from './i18n.svelte.js';

beforeEach(() => setMessages('en', en));

describe('t', () => {
  it('returns the key when missing', () => {
    expect(t('no.such.key')).toBe('no.such.key');
  });
  it('leaves a missing param visible', () => {
    setMessages('en', { a: 'Hi {name}, {n}' });
    expect(t('a', { name: 'Ann' })).toBe('Hi Ann, {n}');
    expect(t('a')).toBe('Hi {name}, {n}');
  });
  it('switches output with setMessages', () => {
    setMessages('en', { k: 'one' });
    setMessages('de', { k: 'eins' });
    expect(t('k')).toBe('eins');
    expect(lang()).toBe('de');
    expect(document.documentElement.lang).toBe('de');
  });
  it('selects Polish plural categories', () => {
    setMessages('pl', { n: { one: 'jeden {count}', few: 'kilka {count}', many: 'wiele {count}', other: 'inne {count}' } });
    const got = [1, 2, 5, 12, 22, 0].map((c) => t('n', { count: c }));
    expect(got).toEqual(['jeden 1', 'kilka 2', 'wiele 5', 'wiele 12', 'kilka 22', 'wiele 0']);
  });
  it('falls back to other for a missing category', () => {
    setMessages('pl', { n: { other: 'x {count}' } });
    expect(t('n', { count: 2 })).toBe('x 2');
  });
});

describe('loadLocale', () => {
  it('keeps messages and does not throw without a bridge', async () => {
    await expect(loadLocale()).resolves.toBeUndefined();
    expect(lang()).toBe('en');
  });
  it('applies a bundle from the bridge', async () => {
    window.pywebview = { api: { i18n_bundle: vi.fn(async () => ({ ok: true, lang: 'es', messages: { k: 'hola' } })) } };
    await loadLocale();
    delete window.pywebview;
    expect(t('k')).toBe('hola');
  });
});

describe('loadLocale late bundle', () => {
  it('still applies a bundle that arrives after the 2 s wait', async () => {
    vi.useFakeTimers();
    try {
      setMessages('en', {});
      window.pywebview = { api: { i18n_bundle: vi.fn(() => new Promise((res) => setTimeout(() => res({ ok: true, lang: 'it', messages: { k: 'ciao' } }), 3000))) } };
      const done = loadLocale();
      await vi.advanceTimersByTimeAsync(2100);
      await done;
      expect(t('k')).toBe('k');
      await vi.advanceTimersByTimeAsync(1500);
      expect(t('k')).toBe('ciao');
      expect(lang()).toBe('it');
    } finally {
      delete window.pywebview;
      vi.useRealTimers();
    }
  });
});

describe('loadLocale ordering', () => {
  it('ignores a slow earlier response that arrives after a newer one', async () => {
    const later = (ms, lang, k) => new Promise((res) => setTimeout(() => res({ ok: true, lang, messages: { k } }), ms));
    vi.useFakeTimers();
    try {
      const replies = [later(1000, 'de', 'alt'), later(100, 'it', 'neu')];
      window.pywebview = { api: { i18n_bundle: vi.fn(() => replies.shift()) } };
      const first = loadLocale();
      const second = loadLocale();
      await vi.advanceTimersByTimeAsync(1500);
      await Promise.all([first, second]);
      expect(t('k')).toBe('neu');
      expect(lang()).toBe('it');
    } finally {
      delete window.pywebview;
      vi.useRealTimers();
    }
  });
});

describe('format', () => {
  it('uses Intl with current lang', () => {
    setMessages('de', {});
    expect(formatNumber(1234.5)).toBe(new Intl.NumberFormat('de').format(1234.5));
    expect(formatDate(new Date(0), { timeZone: 'UTC' })).toBe(new Intl.DateTimeFormat('de', { timeZone: 'UTC' }).format(new Date(0)));
  });
});
