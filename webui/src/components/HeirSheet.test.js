import { afterEach, describe, expect, it, vi } from 'vitest';
import { render } from '@testing-library/svelte';
import { tick } from 'svelte';
import HeirSheet from './HeirSheet.svelte';

const SHEET = {
  owner: 'Ηλίας', plan_id: '0b5f0c43-7f6a-4c2a-9a55-7d3f9f2f9c11', k: 2, n: 3, wait_days: 7, created: '2027-01-15',
  pages: [
    { holder: 'Βασίλης', index: 1, package_id: 'p1', qr_size: 3, qr_path: 'M0 0h1v1h-1z' },
    { holder: 'Μαρία', index: 2, package_id: 'p2', qr_size: 3, qr_path: 'M1 1h2v1h-2z' },
    { holder: '陈', index: 3, package_id: 'p3', qr_size: 3, qr_path: 'M2 2h1v1h-1z' },
  ],
};

afterEach(() => {
  vi.restoreAllMocks();
  document.querySelectorAll('.sheet-portal').forEach((n) => n.remove());
});

const frames = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r())));
const flush = async () => { await tick(); await frames(); await tick(); };

describe('heir shard sheet', () => {
  it('prints one page per holder with Greek and other scripts exactly as typed', async () => {
    const print = vi.spyOn(window, 'print').mockImplementation(() => {});
    const ondone = vi.fn();
    render(HeirSheet, { sheet: SHEET, ondone });
    await flush();
    const pages = [...document.querySelectorAll('[data-testid="heir-page"]')];
    expect(pages).toHaveLength(3);
    expect(pages.map((p) => p.querySelector('[data-testid="heir-holder"]').textContent))
      .toEqual(['Βασίλης', 'Μαρία', '陈']);
    expect(pages[0].textContent).toContain('Ηλίας');
    expect(pages[0].querySelector('svg path').getAttribute('d')).toBe('M0 0h1v1h-1z');
    expect(pages[0].querySelector('svg').getAttribute('viewBox')).toBe('0 0 3 3');
    expect(pages[0].textContent).toContain('act together');
    expect(print).toHaveBeenCalledTimes(1);
    window.dispatchEvent(new Event('afterprint'));
    expect(ondone).toHaveBeenCalledTimes(1);
  });
});
